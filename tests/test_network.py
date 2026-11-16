"""Safety and configuration checks; no network/kernel mutations are performed."""

import importlib.util
from contextlib import contextmanager, ExitStack
import copy
import io
import ipaddress
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch, Mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "runtime" / "network.py"
SPEC = importlib.util.spec_from_file_location("native_network", MODULE_PATH)
network = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(network)


class Result:
    def __init__(self, content="", code=0, stderr=""):
        self.stdout, self.returncode, self.stderr = content, code, stderr


class Firewall:
    def __init__(self, marker, foreign=False):
        self.marker = marker
        self.foreign = foreign
        self.calls = []
        self.rules = [{"priority": 5, "src": "all", "fwmark": "0x2099", "table": 2099}]

    def run(self, argv, **kwargs):
        self.calls.append(argv)
        if argv == ["nft", "-j", "list", "tables"]:
            return Result(json.dumps({"nftables": [{"table": {"family": "inet", "name": "mihomo"}}]}))
        if argv[:4] == ["nft", "-j", "list", "table"]:
            marker = "foreign" if self.foreign else self.marker
            return Result(json.dumps({"nftables": [{"chain": {"family": "inet", "table": "mihomo", "name": marker}}]}))
        if argv[:3] in (["ip", "-4", "-j"], ["ip", "-6", "-j"]):
            return Result(json.dumps(self.rules if argv[1] == "-4" else []))
        if argv == ["ip", "-j", "link", "show", "dev", network.DEVICE]:
            return Result(code=1)
        return Result()


class RecoveryKernel:
    """Mutable kernel substitute: successful commands must really remove state."""

    def __init__(self, marker, *, foreign=False, stubborn=False):
        self.tables = {network.DNS_TABLE: "foreign" if foreign else marker}
        self.rules = {"-4": [{"priority": 5, "src": "all", "fwmark": "0x2099", "table": 2099}], "-6": []}
        self.link = None
        self.routes = {"-4": [], "-6": []}
        self.calls = []
        self.stubborn = stubborn

    def run(self, argv, **kwargs):
        self.calls.append(argv)
        if argv == ["nft", "-j", "list", "tables"]:
            return Result(json.dumps({"nftables": [{"table": {"family": "inet", "name": name}} for name in self.tables]}))
        if argv[:4] == ["nft", "-j", "list", "table"]:
            name = argv[-1]
            return Result(json.dumps({"nftables": [{"chain": {"family": "inet", "table": name, "name": self.tables[name]}}]}))
        if argv[:4] == ["nft", "delete", "table", "inet"]:
            if not self.stubborn:
                self.tables.pop(argv[-1])
            return Result()
        if len(argv) >= 5 and argv[0] == "ip" and argv[1] in ("-4", "-6"):
            family = argv[1]
            if argv[2:] == ["-j", "rule", "show"]:
                return Result(json.dumps(self.rules[family]))
            if argv[2:5] == ["rule", "del", "pref"]:
                self.rules[family] = [rule for rule in self.rules[family] if rule["priority"] != int(argv[-1])]
                return Result()
            if argv[2:6] == ["-j", "route", "show", "table"]:
                return Result(json.dumps(self.routes[family]))
        if argv == ["ip", "-j", "link", "show", "dev", network.DEVICE]:
            return Result(json.dumps([self.link]) if self.link else "[]", 0 if self.link else 1)
        if argv == ["ip", "link", "delete", "dev", network.DEVICE]:
            self.link = None
            self.routes = {"-4": [], "-6": []}
            return Result()
        raise AssertionError("Unexpected kernel command: " + repr(argv))


@contextmanager
def recovery_controller(state, kernel):
    saved = [copy.deepcopy(state)]
    controller = network.NetworkController("v2rayn", "unused", "unused", 10808, excluded_uids=(1500,), state_dir="unused-state")
    original_recover = network._recover_stale
    with ExitStack() as patches:
        patches.enter_context(patch.object(network, "_root_platform"))
        patches.enter_context(patch.object(network, "_private_directory", side_effect=lambda directory: directory))
        patches.enter_context(patch.object(network, "_trusted_file", side_effect=lambda path: path))
        patches.enter_context(patch.object(network, "_read_json", side_effect=lambda path: copy.deepcopy(saved[0])))
        patches.enter_context(patch.object(network, "_write_json", side_effect=lambda path, value: saved.__setitem__(0, copy.deepcopy(value))))
        patches.enter_context(patch.object(network, "_take_lock", return_value=91))
        patches.enter_context(patch.object(network, "_pid_matches", return_value=False))
        patches.enter_context(patch.object(network.time, "sleep"))
        patches.enter_context(patch.object(network.os, "close"))
        patches.enter_context(patch.object(network, "_recover_stale", side_effect=lambda value: original_recover(value, kernel.run)))
        yield controller, saved


class ConfigTests(unittest.TestCase):
    def test_only_loopback_socks_outbound_and_no_node_credentials(self):
        config = network.build_config(10808, excluded_uids=(1500, 1501))
        self.assertEqual(config["proxies"], [{"name": "LOCAL-CLIENT", "type": "socks5", "server": "127.0.0.1", "port": 10808, "udp": True}])
        self.assertEqual(config["tun"]["exclude-uid-range"], ["1500:1501"])
        self.assertNotIn("exclude-uid", config["tun"])
        self.assertNotIn("routing-mark", config)
        self.assertNotIn("include-interface", config["tun"])
        for secret_key in ("password", "uuid", "public-key", "subscription"):
            self.assertNotIn(secret_key, json.dumps(config))

    def test_mark_mode_and_priority_ten_coexistence_are_explicit(self):
        config = network.build_config(17897, excluded_uids=(1500, 1501))
        tun = config["tun"]
        self.assertTrue(tun["auto-route"] and tun["auto-redirect"])
        self.assertEqual(tun["route-address-set"], ["fnproxy-all-addresses"])
        self.assertEqual(config["rule-providers"]["fnproxy-all-addresses"]["payload"], ["0.0.0.0/0", "::/0"])
        self.assertEqual(tun["iproute2-table-index"], 2099)
        self.assertEqual(tun["iproute2-rule-index"], 19000)
        self.assertNotIn(10, network._RESERVED_PRIORITIES)
        for priority, selector in network._supplement_specs():
            self.assertLess(priority, 10)
            self.assertEqual(selector[0], "fwmark")

    def test_management_and_private_traffic_have_multiple_bypass_layers(self):
        config = network.build_config(10808, excluded_uids=(1500,))
        exclusions = config["tun"]["route-exclude-address"]
        for value in ("127.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "100.64.0.0/10", "fe80::/10"):
            self.assertIn(value, exclusions)
        for process in ("tailscaled", "xray", "sing-box", "verge-mihomo"):
            self.assertIn(f"PROCESS-NAME,{process},DIRECT", config["rules"])
        self.assertEqual(config["tun"]["exclude-interface"], ["tailscale0"])
        self.assertEqual(config["tun"]["dns-mode"], "disabled")
        self.assertTrue(all(server.endswith("#LOCAL-CLIENT") for server in config["dns"]["nameserver"]))
        self.assertEqual(config["rules"][-1], "MATCH,LOCAL-CLIENT")

    def test_ipv6_fake_pool_is_the_only_ula_hole_in_both_bypass_layers(self):
        config = network.build_config(10808, excluded_uids=(969, 970))
        self.assertTrue(config["ipv6"] and config["dns"]["ipv6"])
        self.assertEqual(config["dns"]["fake-ip-range6"], "fdfe:dcba:9876::/64")
        pool = ipaddress.ip_network(config["dns"]["fake-ip-range6"])
        ula = ipaddress.ip_network("fc00::/7")
        layers = {
            "route": [ipaddress.ip_network(value) for value in config["tun"]["route-exclude-address"] if ":" in value],
            "direct": [ipaddress.ip_network(rule.split(",")[1]) for rule in config["rules"] if rule.startswith("IP-CIDR6,")],
        }
        self.assertEqual(set(layers["route"]), set(layers["direct"]))
        for name, prefixes in layers.items():
            with self.subTest(layer=name):
                self.assertTrue(all(not prefix.overlaps(pool) for prefix in prefixes))
                ula_prefixes = [prefix for prefix in prefixes if prefix.subnet_of(ula)]
                self.assertEqual(len(ula_prefixes), 57)
                # Sorting the complement plus the pool must partition the ULA
                # interval exactly: no overlap and no other missing addresses.
                ordered = sorted([*ula_prefixes, pool], key=lambda prefix: int(prefix.network_address))
                self.assertEqual(ordered[0].network_address, ula.network_address)
                self.assertEqual(ordered[-1].broadcast_address, ula.broadcast_address)
                for left, right in zip(ordered, ordered[1:]):
                    self.assertEqual(int(left.broadcast_address) + 1, int(right.network_address))
                for offset, bypassed in ((-1, True), (0, False), (1, False),
                                         (pool.num_addresses - 1, False), (pool.num_addresses, True)):
                    address = ipaddress.IPv6Address(int(pool.network_address) + offset)
                    self.assertEqual(any(address in prefix for prefix in prefixes), bypassed, str(address))

    def test_ordinary_ula_tailnet_and_actual_tun_ipv6_stay_direct(self):
        config = network.build_config(10808, excluded_uids=(969, 970))
        self.assertEqual(config["tun"]["inet6-address"], ["fdfe:dcba:2099::1/126"])
        layers = (
            [ipaddress.ip_network(value) for value in config["tun"]["route-exclude-address"] if ":" in value],
            [ipaddress.ip_network(rule.split(",")[1]) for rule in config["rules"] if rule.startswith("IP-CIDR6,")],
        )
        for prefixes in layers:
            for protected in ("fd7a:115c:a1e0::/48", "fdfe:dcba:2099::/126"):
                self.assertTrue(any(ipaddress.ip_network(protected).subnet_of(prefix) for prefix in prefixes), protected)
            for address in ("fc00::", "fd00::1234", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe80::1", "::1"):
                self.assertTrue(any(ipaddress.ip_address(address) in prefix for prefix in prefixes), address)
            for address in ("2606:4700:4700::1111", "2001:4860:4860::8888"):
                self.assertFalse(any(ipaddress.ip_address(address) in prefix for prefix in prefixes), address)

    def test_invalid_or_root_uid_exclusions_fail_closed(self):
        for excluded in ((), (0,), (-1,), (True,), (2**32 - 1,), (2**32,)):
            with self.subTest(excluded=excluded), self.assertRaises(ValueError):
                network.build_config(10808, excluded_uids=excluded)
        for port in (0, True, "10808", 65536):
            with self.subTest(port=port), self.assertRaises(ValueError):
                network.build_config(port, excluded_uids=(1500,))

    def test_uid_ranges_merge_only_consecutive_unique_ids(self):
        for supplied, expected in (
            ([970, 969, 969], ["969:970"]),
            ([969, 971], ["969:969", "971:971"]),
            ([1500, 1501, 1600], ["1500:1501", "1600:1600"]),
            ([1600, 1501, 1500, 1501], ["1500:1501", "1600:1600"]),
        ):
            with self.subTest(supplied=supplied):
                tun = network.build_config(10808, excluded_uids=supplied)["tun"]
                self.assertEqual(tun["exclude-uid-range"], expected)
                self.assertNotIn("exclude-uid", tun)

    def test_uid_ranges_keep_valid_boundary_ids_separate(self):
        tun = network.build_config(10808, excluded_uids=(2**32 - 2, 1))["tun"]
        self.assertEqual(tun["exclude-uid-range"], ["1:1", "4294967294:4294967294"])
        self.assertEqual(network._uids((970, 969, 969)), [969, 970])

    def test_host_and_bridge_dns_have_scoped_rules(self):
        marker = "fnproxy_owner_" + "a" * 24
        rules = network._dns_rules(["br-test", "docker0"], [1500, 1501], marker)
        self.assertIn("create table inet fnproxy_dns", rules)
        self.assertIn('iifname { "br-test", "docker0" } udp dport 53 redirect to :15353', rules)
        self.assertIn("meta skuid { 1500, 1501 } return", rules)
        self.assertIn("meta mark & 0xff0000 == 0x80000 return", rules)
        self.assertNotIn("resolv.conf", rules)
        self.assertNotIn("flush", rules)
        for name in ('bad"; flush ruleset', "br-a\nflush ruleset"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                network._dns_rules([name], [1500], marker)


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.marker = "fnproxy_owner_" + "a" * 24

    def test_cleanup_deletes_only_marked_table_and_exact_recorded_rules(self):
        firewall = Firewall(self.marker)
        state = {"marker": self.marker, "rules": {"-4": firewall.rules.copy(), "-6": []}}
        network._cleanup_owned(state, firewall.run)
        deletes = [call for call in firewall.calls if "delete" in call or "del" in call]
        self.assertEqual(deletes, [["nft", "delete", "table", "inet", "mihomo"], ["ip", "-4", "rule", "del", "pref", "5"]])
        self.assertFalse(any("flush" in call or "iptables" in call for call in firewall.calls))

    def test_foreign_table_is_not_deleted_even_when_name_matches(self):
        firewall = Firewall(self.marker, foreign=True)
        with self.assertRaisesRegex(network.NetworkError, "ownership marker"):
            network._cleanup_owned({"marker": self.marker, "rules": {}}, firewall.run)
        self.assertFalse(any("delete" in call for call in firewall.calls))

    def test_changed_routing_rule_is_not_deleted(self):
        firewall = Firewall(self.marker)
        expected = {"priority": 5, "src": "all", "table": 2099}
        with self.assertRaisesRegex(network.NetworkError, "changed"):
            network._remove_recorded_rule("-4", expected, firewall.run)
        self.assertFalse(any("del" in call for call in firewall.calls))

    def test_non_owned_priority_is_never_removed(self):
        firewall = Firewall(self.marker)
        with self.assertRaisesRegex(network.NetworkError, "unowned"):
            network._remove_recorded_rule("-4", {"priority": 10}, firewall.run)
        self.assertEqual(firewall.calls, [])

    def test_snapshot_rejects_foreign_rule_in_reserved_slot(self):
        state = {"rules": {"-4": [], "-6": []}}
        foreign = [{"priority": 5, "src": "all", "table": "main"}]
        with patch.object(network, "_rules", return_value=foreign):
            with self.assertRaisesRegex(network.NetworkError, "unexpected rule"):
                network._snapshot_rules(state)
        self.assertEqual(state["rules"], {"-4": [], "-6": []})

    def test_actual_iproute2_nop_flag_is_recorded_and_cleaned(self):
        rule = {"priority": 19002, "src": "all", "nop": None}
        state = {"rules": {"-4": [], "-6": []}}
        with patch.object(network, "_rules", side_effect=lambda family: [rule] if family == "-4" else []):
            network._snapshot_rules(state)
        self.assertEqual(state["rules"]["-4"], [rule])
        kernel = RecoveryKernel(self.marker)
        kernel.tables = {}; kernel.rules = {"-4": [rule], "-6": []}
        state.update(rule_claims={"-4": [19002], "-6": []}, table_claims=[])
        network._cleanup_owned(state, kernel.run)
        network._verify_absent(state, kernel.run)
        self.assertEqual(kernel.rules["-4"], [])

    def test_inverted_and_extra_selectors_cannot_be_claimed(self):
        valid = {"priority": 5, "src": "all", "fwmark": "0x2099", "table": "2099"}
        for extra in ({"not": None}, {"iif": "eth0"}, {"uidrange": "1000-1000"}, {"goto": 123}):
            self.assertFalse(network._expected_owned_rule({**valid, **extra}))
        for nop in ({"priority": 19002, "nop": False}, {"priority": 19002, "nop": None, "action": "nop"}):
            self.assertFalse(network._expected_owned_rule(nop))
        self.assertTrue(network._expected_owned_rule({"priority": 19002, "action": "nop"}))

    def test_stop_cannot_signal_the_other_clients_guardian(self):
        controller = network.NetworkController("v2rayn", "unused", "unused", 10808, excluded_uids=(1500,))
        with patch.object(network, "_root_platform"), patch.object(network, "_read_json", return_value={"app": "clash"}):
            with patch.object(network.os, "kill") as kill:
                with self.assertRaises(network.NetworkBusy):
                    controller.stop()
                kill.assert_not_called()

    def test_recycled_core_pid_is_never_signaled(self):
        with patch.object(network, "_pid_matches", return_value=False), patch.object(network.os, "kill") as kill:
            network._terminate_core({"core_pid": 12345, "core_start": "expired"})
            kill.assert_not_called()

    @unittest.skipIf(network.fcntl is None, "Linux/POSIX flock requires NAS verification")
    def test_lease_prevents_both_clients_from_owning_network(self):
        with tempfile.TemporaryDirectory() as directory:
            first = network._take_lock(Path(directory))
            try:
                with self.assertRaises(network.NetworkBusy):
                    network._take_lock(Path(directory))
            finally:
                os.close(first)
            second = network._take_lock(Path(directory))
            os.close(second)


class HealthTests(unittest.TestCase):
    def test_firewall_waits_for_redirect_chains_after_address_sets(self):
        marker = "fnproxy_owner_" + "a" * 24
        def content(names):
            return Result(json.dumps({"nftables": [{"table": {"family": "inet", "name": "mihomo"}},
                {"set": {"name": "inet4_route_address_set"}},
                *[{"chain": {"family": "inet", "table": "mihomo", "name": name}} for name in names]]}))
        partial = content([marker])
        complete = content([marker, "output", "output_udp_icmp", "prerouting", "prerouting_udp_icmp"])
        with patch.object(network, "_run", side_effect=[partial, complete]) as runner, patch.object(network.time, "sleep") as sleep:
            network._await_core_firewall(marker, Mock(poll=Mock(return_value=None)), lambda: False)
        self.assertEqual(runner.call_count, 2); sleep.assert_called_once()

    def test_firewall_readiness_timeout_retains_marker_for_owned_cleanup(self):
        marker = "fnproxy_owner_" + "a" * 24
        partial = Result(json.dumps({"nftables": [{"chain": {"family": "inet", "table": "mihomo", "name": marker}}]}))
        with patch.object(network, "_run", return_value=partial), patch.object(network.time, "sleep"), patch.object(network.time, "monotonic", side_effect=[0, 0, 13]):
            with self.assertRaisesRegex(network.NetworkError, "finish creating"):
                network._await_core_firewall(marker, Mock(poll=Mock(return_value=None)), lambda: False)
        kernel = RecoveryKernel(marker); kernel.tables = {"mihomo": marker}; kernel.rules = {"-4": [], "-6": []}
        state = {"marker": marker, "table_claims": ["mihomo"], "rules": {"-4": [], "-6": []}}
        network._cleanup_owned(state, kernel.run); network._verify_absent(state, kernel.run)
        self.assertEqual(kernel.tables, {})

    def test_firewall_readiness_rejects_lost_ownership(self):
        partial = Result(json.dumps({"nftables": []}))
        with patch.object(network, "_run", return_value=partial):
            with self.assertRaisesRegex(network.NetworkError, "ownership marker changed"):
                network._await_core_firewall("fnproxy_owner_" + "a" * 24, Mock(poll=Mock(return_value=None)), lambda: False)

    def test_unready_socks_fails_before_kernel_operations(self):
        with patch.object(network, "socks_ready", return_value=False), patch.object(network, "_run") as runner:
            with self.assertRaisesRegex(network.NetworkError, "SOCKS5"):
                network._preflight({"socks_port": 10808})
            runner.assert_not_called()

    def test_socks_health_requires_a_valid_protocol_handshake(self):
        for response, expected in ((b"\x05\x00", True), (b"\x05\xff", False), (b"HT", False)):
            server = socket.socket()
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]
            def serve():
                with server:
                    client, _ = server.accept()
                    with client:
                        client.recv(3)
                        client.sendall(response)
            thread = threading.Thread(target=serve)
            thread.start()
            self.assertEqual(network.socks_ready(port), expected)
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

    def test_management_route_requires_the_expected_device(self):
        for device, expected in (("tailscale0", True), ("eth9", False), ("fnproxy0", False)):
            def runner(_argv, **_kwargs):
                return Result(json.dumps([{"dev": device}]))
            self.assertEqual(network._management_ok("100.64.0.10", "tailscale0", runner), expected)

    def test_invalid_controller_inputs_cannot_target_arbitrary_hosts(self):
        with self.assertRaises(ValueError):
            network.NetworkController("bad", "unused", "unused", 10808, excluded_uids=(1500,))
        with self.assertRaises(ValueError):
            network.NetworkController("v2rayn", "unused", "unused", 10808, excluded_uids=(1500,), management_target="8.8.8.8")


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.marker = "fnproxy_owner_" + "a" * 24
        self.state = {"app": "v2rayn", "token": "a" * 24, "marker": self.marker,
                      "phase": "active", "guard_pid": 12345, "guard_start": "old-guardian",
                      "core_pid": 23456, "core_start": "old-core", "cleanup_verified": False,
                      "table_claims": [network.DNS_TABLE], "tun_claimed": False, "route_table_claimed": True,
                      "rules": {"-4": [{"priority": 5, "src": "all", "fwmark": "0x2099", "table": 2099}], "-6": []}}

    def test_guard_finally_cleans_even_when_every_state_save_fails(self):
        state = copy.deepcopy(self.state)
        order = []
        with patch.object(network, "_write_json", side_effect=OSError("state disk failed")), patch.object(network.sys, "stderr", io.StringIO()):
            with patch.object(network, "_terminate_core", side_effect=lambda value: order.append("terminate")):
                with patch.object(network, "_cleanup_owned", side_effect=lambda value: order.append("cleanup")):
                    with patch.object(network, "_verify_absent", side_effect=lambda value: order.append("verify")):
                        with patch.object(network.os, "close", side_effect=lambda fd: order.append("close")):
                            network._finish_guard(state, Path("unused"), 91, None, None)
        self.assertEqual(order, ["terminate", "cleanup", "verify", "close"])
        self.assertTrue(state["cleanup_verified"])
        self.assertEqual(state["phase"], "error")
        self.assertIn("state disk failed", state["last_error"])

    def test_guard_failure_in_one_cleanup_step_does_not_skip_the_next(self):
        state = copy.deepcopy(self.state)
        with patch.object(network, "_write_json"), patch.object(network, "_terminate_core", side_effect=network.NetworkError("termination failed")):
            with patch.object(network, "_cleanup_owned") as cleanup, patch.object(network, "_verify_absent", side_effect=network.NetworkError("core still alive")):
                with patch.object(network.os, "close") as close:
                    network._finish_guard(state, Path("unused"), 91, None, None)
        cleanup.assert_called_once()
        close.assert_called_once_with(91)
        self.assertFalse(state["cleanup_verified"])
        self.assertEqual(state["phase"], "error")

    def test_maintain_recovers_dns_table_after_guardian_sigkill(self):
        kernel = RecoveryKernel(self.marker)
        with recovery_controller(self.state, kernel) as (controller, saved):
            result = controller.maintain()
            self.assertFalse(result["active"])
            self.assertTrue(result["cleanup_verified"])
            self.assertTrue(result["recovered"])
            self.assertEqual(saved[0]["phase"], "stopped")
            self.assertEqual(kernel.tables, {})
            self.assertEqual(kernel.rules, {"-4": [], "-6": []})
            prior_calls = copy.deepcopy(kernel.calls)
            controller.maintain()
            self.assertEqual(kernel.calls, prior_calls)

    def test_repeated_explicit_recovery_is_idempotent(self):
        kernel = RecoveryKernel(self.marker)
        with recovery_controller(self.state, kernel) as (controller, saved):
            controller.recover()
            first_deletions = [call for call in kernel.calls if "delete" in call or "del" in call]
            controller.recover()
            self.assertEqual([call for call in kernel.calls if "delete" in call or "del" in call], first_deletions)
            self.assertTrue(saved[0]["cleanup_verified"])

    def test_stop_does_not_report_success_when_delete_succeeds_but_resources_remain(self):
        kernel = RecoveryKernel(self.marker, stubborn=True)
        with recovery_controller(self.state, kernel) as (controller, saved):
            with self.assertRaisesRegex(network.NetworkError, "resource absence"):
                controller.stop()
            self.assertEqual(saved[0]["phase"], "error")
            self.assertFalse(saved[0]["cleanup_verified"])
            self.assertEqual(saved[0]["token"], self.state["token"])
        self.assertEqual(sum(call == ["nft", "delete", "table", "inet", network.DNS_TABLE] for call in kernel.calls), 2)

    def test_stop_retries_a_guardians_recorded_cleanup_error(self):
        state = {**self.state, "phase": "error", "last_error": "earlier cleanup refused"}
        kernel = RecoveryKernel(self.marker)
        with recovery_controller(state, kernel) as (controller, saved):
            result = controller.stop()
            self.assertTrue(result["cleanup_verified"])
            self.assertEqual(saved[0]["previous_error"], "earlier cleanup refused")
            self.assertIsNone(saved[0]["last_error"])

    def test_live_guardian_exit_with_cleanup_error_still_blocks_stop_success(self):
        kernel = RecoveryKernel(self.marker, stubborn=True)
        with recovery_controller(self.state, kernel) as (controller, saved):
            alive = [True]
            def guardian_exits(pid, start, signum):
                self.assertEqual(pid, self.state["guard_pid"])
                alive[0] = False
                saved[0].update(phase="error", last_error="guardian cleanup failed", cleanup_verified=False)
            with patch.object(network, "_pid_matches", side_effect=lambda pid, start: pid == self.state["guard_pid"] and alive[0]):
                with patch.object(network, "_signal_matching_pid", side_effect=guardian_exits) as send:
                    with self.assertRaisesRegex(network.NetworkError, "resource absence"):
                        controller.stop()
            send.assert_called_once()
            self.assertFalse(saved[0]["cleanup_verified"])

    def test_final_state_save_failure_does_not_change_verified_cleanup_into_success(self):
        state = copy.deepcopy(self.state)
        with patch.object(network, "_write_json", side_effect=[None, OSError("final state failed")]):
            with patch.object(network, "_terminate_core"), patch.object(network, "_cleanup_owned"), patch.object(network, "_verify_absent"):
                with patch.object(network.os, "close") as close, patch.object(network.sys, "stderr", io.StringIO()):
                    network._finish_guard(state, Path("unused"), 91, None, None)
        self.assertEqual(state["phase"], "error")
        self.assertIn("final state failed", state["last_error"])
        close.assert_called_once_with(91)

    def test_foreign_marker_is_preserved_and_recovery_does_not_erase_owner(self):
        kernel = RecoveryKernel(self.marker, foreign=True)
        with recovery_controller(self.state, kernel) as (controller, saved):
            with self.assertRaises(network.NetworkError):
                controller.recover()
            self.assertFalse(saved[0]["cleanup_verified"])
            self.assertEqual(saved[0]["token"], self.state["token"])
        self.assertFalse(any(call[:4] == ["nft", "delete", "table", "inet"] for call in kernel.calls))
        self.assertEqual(kernel.tables[network.DNS_TABLE], "foreign")

    def test_start_cannot_overwrite_stale_owner_before_successful_cleanup(self):
        kernel = RecoveryKernel(self.marker, stubborn=True)
        with recovery_controller(self.state, kernel) as (controller, saved):
            original = copy.deepcopy(saved[0])
            plan = {"interface": "eth9", "lan_gateway": "10.42.0.1", "tailscale": False,
                    "management_checks": [{"target": "10.42.0.1", "device": "eth9"}]}
            with patch.object(network, "_discover_network", return_value=plan) as discover:
                with patch.object(network, "_recover_stale", wraps=network._recover_stale) as recover:
                    with patch.object(network.subprocess, "Popen") as spawn:
                        with self.assertRaisesRegex(network.NetworkError, "resource absence"):
                            controller.start()
                    recover.assert_called_once_with(original)
                discover.assert_called_once()
            spawn.assert_not_called()
            self.assertEqual(saved[0], original)
            self.assertEqual(sum(call == ["nft", "delete", "table", "inet", network.DNS_TABLE] for call in kernel.calls), 2)

    def test_pending_rule_claim_closes_add_before_snapshot_sigkill_window(self):
        state = {**self.state, "rules": {"-4": [], "-6": []}, "rule_claims": {"-4": [5], "-6": []}}
        kernel = RecoveryKernel(self.marker)
        with patch.object(network, "_pid_matches", return_value=False):
            network._recover_stale(state, kernel.run)
        self.assertEqual(kernel.rules["-4"], [])

    def test_changed_pending_rule_selector_is_never_adopted(self):
        state = {**self.state, "rules": {"-4": [], "-6": []}, "rule_claims": {"-4": [5], "-6": []}}
        kernel = RecoveryKernel(self.marker)
        kernel.rules["-4"][0]["table"] = "main"
        with patch.object(network, "_pid_matches", return_value=False), patch.object(network.time, "sleep"):
            with self.assertRaises(network.NetworkError):
                network._recover_stale(state, kernel.run)
        self.assertFalse(any(call[:4] == ["ip", "-4", "rule", "del"] for call in kernel.calls))

    def test_pidfd_recheck_prevents_signaling_a_reused_pid(self):
        with patch.object(network, "_pid_matches", side_effect=[True, False]):
            with patch.object(network.os, "pidfd_open", return_value=91, create=True):
                with patch.object(network.signal, "pidfd_send_signal", create=True) as send:
                    with patch.object(network.os, "close") as close:
                        self.assertFalse(network._signal_matching_pid(12345, "old", network.signal.SIGTERM))
        send.assert_not_called()
        close.assert_called_once_with(91)

    def test_owner_change_between_dead_guardian_check_and_lease_is_not_overwritten(self):
        other = {**self.state, "app": "clash", "token": "b" * 24, "guard_pid": 34567, "guard_start": "new"}
        controller = network.NetworkController("v2rayn", "unused", "unused", 10808, excluded_uids=(1500,), state_dir="unused-state")
        with patch.object(network, "_root_platform"), patch.object(network, "_private_directory", side_effect=lambda path: path):
            with patch.object(network, "_read_json", side_effect=[self.state, self.state, other, other]):
                with patch.object(network, "_pid_matches", side_effect=lambda pid, start: pid == 34567):
                    with patch.object(network, "_take_lock", return_value=91), patch.object(network.os, "close"):
                        with patch.object(network, "_write_json") as save, patch.object(network, "_recover_stale") as recover:
                            result = controller.maintain()
        self.assertEqual(result["owner"], "clash")
        self.assertTrue(result["active"])
        recover.assert_not_called()
        save.assert_not_called()

    def test_preflight_failure_does_not_claim_or_touch_existing_foreign_resources(self):
        state = {"marker": self.marker, "table_claims": [], "rule_claims": {"-4": [], "-6": []},
                 "rules": {"-4": [], "-6": []}, "tun_claimed": False, "route_table_claimed": False}
        kernel = RecoveryKernel(self.marker, foreign=True)
        network._cleanup_owned(state, kernel.run)
        network._verify_absent(state, kernel.run)
        self.assertEqual(kernel.calls, [])


if __name__ == "__main__":
    unittest.main()
