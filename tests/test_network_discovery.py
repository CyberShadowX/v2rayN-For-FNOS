"""Portable discovery and guardian checks; every kernel/tool operation is fake."""

import copy
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("discovery_network", REPO / "runtime" / "network.py")
network = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(network)

DEFAULT_QUERY = ["ip", "-4", "-j", "route", "show", "table", "main", "default"]
LINK_QUERY = ["ip", "-j", "link", "show"]
TAILSCALE_QUERY = ["tailscale", "status", "--json"]


def result(value=None, *, code=0, raw=None):
    return subprocess.CompletedProcess([], code, stdout=json.dumps(value) if raw is None else raw, stderr="")


class LocalNetwork:
    def __init__(self, *, tailscale=False):
        self.routes = [{"dst": "default", "gateway": "10.42.0.1", "dev": "eth9"}]
        self.links = [{"ifname": "lo", "flags": ["UP", "LOOPBACK"]}, {"ifname": "eth9", "flags": ["UP"]}]
        self.peers = {"BackendState": "Running", "Peer": {
            "online": {"Online": True, "TailscaleIPs": ["100.64.0.10", "fd7a:115c:a1e0::10"]},
            "offline": {"Online": False, "TailscaleIPs": ["100.64.0.9"]},
        }}
        if tailscale:
            self.links.append({"ifname": "tailscale0", "flags": ["UP"]})
        self.overrides = {}
        self.calls = []

    def run(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        if tuple(argv) in self.overrides:
            value = self.overrides[tuple(argv)]
            if isinstance(value, BaseException):
                raise value
            return value
        if argv == DEFAULT_QUERY:
            return result(self.routes)
        if argv == LINK_QUERY:
            return result(self.links)
        if argv == TAILSCALE_QUERY:
            return result(self.peers)
        if argv[:4] == ["ip", "-j", "route", "get"] or argv[:5] == ["ip", "-6", "-j", "route", "get"]:
            return result([{"dev": "tailscale0" if network._tailnet_address(argv[-1]) else "eth9"}])
        raise AssertionError("Discovery attempted an unexpected operation: " + repr(argv))


class GuardianKernel:
    """Minimal stateful kernel: cleanup must actually remove each owned object."""

    def __init__(self, marker, fail_target, passes):
        self.marker, self.fail_target, self.passes = marker, fail_target, passes
        self.rules = {"-4": [], "-6": []}
        self.tables = {}
        self.link = None
        self.route_checks = {}
        self.calls = []

    def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv[0] == "native-mihomo":
            return result()
        if argv[:4] == ["ip", "-j", "route", "get"]:
            target = argv[-1]
            self.route_checks[target] = self.route_checks.get(target, 0) + 1
            device = "tailscale0" if network._tailnet_address(target) else "eth9"
            if target == self.fail_target and self.route_checks[target] > self.passes:
                device = network.DEVICE
            return result([{"dev": device}])
        if argv == ["ip", "-j", "link", "show", "dev", network.DEVICE]:
            return result([self.link] if self.link else [], code=0 if self.link else 1)
        if argv == ["ip", "link", "delete", "dev", network.DEVICE]:
            self.link = None
            return result()
        if argv[0] == "ip" and len(argv) > 2 and argv[1] in ("-4", "-6"):
            family = argv[1]
            if argv[2:] == ["-j", "rule", "show"]:
                return result(copy.deepcopy(self.rules[family]))
            if argv[2:6] == ["-j", "route", "show", "table"]:
                return result([])
            if argv[2:5] == ["rule", "add", "pref"]:
                mark, *mask = argv[7].split("/")
                rule = {"priority": int(argv[5]), "src": "all", "fwmark": mark, "table": argv[-1]}
                if mask:
                    rule["fwmask"] = mask[0]
                self.rules[family].append(rule)
                return result()
            if argv[2:5] == ["rule", "del", "pref"]:
                self.rules[family] = [row for row in self.rules[family] if row["priority"] != int(argv[-1])]
                return result()
        if argv[:4] == ["nft", "create", "chain", "inet"]:
            self.tables[argv[-2]] = argv[-1]
            return result()
        if argv[:4] == ["nft", "insert", "rule", "inet"]:
            return result()
        if argv == ["nft", "-f", "-"]:
            self.tables[network.DNS_TABLE] = self.marker
            return result()
        if argv == ["nft", "-j", "list", "tables"]:
            return result({"nftables": [{"table": {"family": "inet", "name": name}} for name in self.tables]})
        if argv[:4] == ["nft", "-j", "list", "table"]:
            return result({"nftables": [{"chain": {"family": "inet", "table": argv[-1], "name": self.tables[argv[-1]]}}]})
        if argv[:4] == ["nft", "delete", "table", "inet"]:
            self.tables.pop(argv[-1])
            return result()
        raise AssertionError("Unexpected guardian command: " + repr(argv))


class DiscoveryTests(unittest.TestCase):
    def test_configuration_without_discovery_has_no_deployment_addresses_or_dependencies(self):
        with patch.object(network, "_run") as runner:
            config = network.build_config(10808, excluded_uids=(1500,))
        runner.assert_not_called()
        self.assertNotIn("interface-name", config)
        self.assertTrue(config["tun"]["auto-detect-interface"])
        self.assertEqual(config["dns"]["nameserver-policy"], {"+.lan": "system", "+.local": "system"})

    def test_non_enp_interface_and_lan_gateway_need_no_tailscale(self):
        local = LocalNetwork()
        plan = network._discover_network(runner=local.run)
        self.assertEqual(plan["interface"], "eth9")
        self.assertEqual(plan["lan_gateway"], "10.42.0.1")
        self.assertEqual(plan["management_checks"], [{"target": "10.42.0.1", "device": "eth9"}])
        self.assertFalse(plan["tailscale"])
        self.assertEqual([call for call, _ in local.calls], [DEFAULT_QUERY, LINK_QUERY, ["ip", "-j", "route", "get", "10.42.0.1"]])
        self.assertTrue(all(kwargs == {"timeout": 5} for _, kwargs in local.calls))
        config = network.build_config(10808, excluded_uids=(1500,), interface=plan["interface"],
                                      lan_gateway=plan["lan_gateway"], tailscale=plan["tailscale"])
        self.assertEqual(config["interface-name"], "eth9")
        self.assertFalse(config["tun"]["auto-detect-interface"])
        self.assertEqual(config["dns"]["nameserver-policy"], {"+.lan": "10.42.0.1", "+.local": "10.42.0.1"})

    def test_online_peer_protects_tailscale_in_addition_to_lan(self):
        local = LocalNetwork(tailscale=True)
        plan = network._discover_network(runner=local.run)
        self.assertEqual(plan["management_checks"], [{"target": "10.42.0.1", "device": "eth9"},
                                                     {"target": "100.64.0.10", "device": "tailscale0"}])
        self.assertEqual(plan["management_target"], "100.64.0.10")
        self.assertIn(TAILSCALE_QUERY, [call for call, _ in local.calls])
        config = network.build_config(10808, excluded_uids=(1500,), interface=plan["interface"],
                                      lan_gateway=plan["lan_gateway"], tailscale=plan["tailscale"])
        self.assertEqual(config["dns"]["nameserver-policy"]["+.ts.net"], "100.100.100.100")

    def test_explicit_interface_can_resolve_two_exits_but_must_still_be_unique(self):
        local = LocalNetwork()
        local.routes.append({"dst": "default", "gateway": "172.20.1.1", "dev": "eth8"})
        local.links.append({"ifname": "eth8", "flags": ["UP"]})
        self.assertEqual(network._discover_network(interface="eth9", runner=local.run)["interface"], "eth9")
        local.routes.append(copy.deepcopy(local.routes[0]))
        with self.assertRaisesRegex(network.NetworkError, "ambiguous"):
            network._discover_network(interface="eth9", runner=local.run)

    def test_explicit_lan_target_adds_a_check_without_replacing_the_gateway(self):
        plan = network._discover_network(interface="eth9", management_target="10.42.0.2", runner=LocalNetwork().run)
        self.assertEqual(plan["management_checks"], [{"target": "10.42.0.1", "device": "eth9"},
                                                     {"target": "10.42.0.2", "device": "eth9"}])

    def test_explicit_ipv6_tailnet_target_requires_an_online_peer_and_fixed_device(self):
        local = LocalNetwork(tailscale=True)
        plan = network._discover_network(management_target="fd7a:115c:a1e0::10", management_device="tailscale0", runner=local.run)
        self.assertEqual(plan["management_checks"][1]["target"], "fd7a:115c:a1e0::10")
        self.assertIn(["ip", "-6", "-j", "route", "get", "fd7a:115c:a1e0::10"], [call for call, _ in local.calls])
        for target, device in (("100.64.0.9", None), ("100.64.0.10", "eth9")):
            with self.subTest(target=target, device=device), self.assertRaises(network.NetworkError):
                network._discover_network(management_target=target, management_device=device, runner=local.run)

    def test_no_or_ambiguous_default_routes_are_rejected(self):
        for routes in ([], [{"dst": "default", "gateway": "10.42.0.1", "dev": "eth9"}] * 2):
            with self.subTest(routes=routes):
                local = LocalNetwork(); local.routes = routes
                with self.assertRaises(network.NetworkError):
                    network._discover_network(runner=local.run)
                self.assertEqual([call for call, _ in local.calls], [DEFAULT_QUERY])

    def test_malformed_or_unsupported_routes_are_rejected(self):
        cases = [None, {}, [None], [{"dst": "default", "gateway": "8.8.8.8", "dev": "eth9"}],
                 [{"dst": "default", "gateway": "127.0.0.1", "dev": "eth9"}],
                 [{"dst": "default", "gateway": "100.64.0.1", "dev": "eth9"}],
                 [{"dst": "default", "gateway": "fd00::1", "dev": "eth9"}]]
        base = {"dst": "default", "gateway": "10.42.0.1", "dev": "eth9"}
        cases += [[{**base, **change}] for change in (
            {"dev": "--help"}, {"dev": 'eth9";id'}, {"dev": "eth9\nid"}, {"dev": "tailscale0"},
            {"gateway": 123}, {"gateway": "10.42.0.1;id"}, {"dst": "10.0.0.0/8"}, {"table": 52},
            {"type": "blackhole"}, {"nexthops": []}, {"nhid": 1}, {"flags": ["linkdown"]}, {"flags": "up"},
        )]
        for routes in cases:
            with self.subTest(routes=routes):
                local = LocalNetwork(); local.routes = routes
                with self.assertRaises(network.NetworkError):
                    network._discover_network(runner=local.run)

    def test_malformed_or_missing_interfaces_are_rejected(self):
        cases = [[], {}, [None], [{"ifname": "eth8", "flags": ["UP"]}],
                 [{"ifname": "eth9", "flags": []}], [{"ifname": "eth9", "flags": "UP"}],
                 [{"ifname": "eth9;id", "flags": ["UP"]}], [{"ifname": "eth9", "flags": ["UP"]}] * 2]
        for links in cases:
            with self.subTest(links=links):
                local = LocalNetwork(); local.links = links
                with self.assertRaises(network.NetworkError):
                    network._discover_network(runner=local.run)

    def test_bad_json_failed_timeout_duplicate_properties_and_oversized_output_are_rejected(self):
        for response in (result(raw="{"), result(code=1), result(raw='[{"dst":"default","dst":"bad"}]'),
                         result(raw="NaN"), result(raw=" " * (network._DISCOVERY_MAX_BYTES + 1)),
                         OSError("missing tool"), subprocess.TimeoutExpired(DEFAULT_QUERY, 5)):
            with self.subTest(response=type(response).__name__):
                local = LocalNetwork(); local.overrides[tuple(DEFAULT_QUERY)] = response
                with self.assertRaises(network.NetworkError):
                    network._discover_network(runner=local.run)

    def test_present_tailscale_without_a_valid_cli_fails_closed(self):
        for response in (FileNotFoundError("missing CLI"), subprocess.TimeoutExpired(TAILSCALE_QUERY, 5),
                         result(code=1), result(raw="{")):
            with self.subTest(response=type(response).__name__):
                local = LocalNetwork(tailscale=True); local.overrides[tuple(TAILSCALE_QUERY)] = response
                with self.assertRaisesRegex(network.NetworkError, "Tailscale CLI"):
                    network._discover_network(runner=local.run)

    def test_untrusted_tailscale_tool_is_rejected_before_execution(self):
        with patch.object(network.Path, "is_file", return_value=True), patch.object(network.os, "access", return_value=True):
            with patch.object(network, "_trusted_file", side_effect=network.NetworkError("untrusted executable")) as trust:
                with patch.object(network.subprocess, "run") as execute:
                    with self.assertRaisesRegex(network.NetworkError, "untrusted"):
                        network._run(TAILSCALE_QUERY, timeout=5)
        trust.assert_called_once_with(Path("/usr/sbin/tailscale"))
        execute.assert_not_called()

    def test_tailscale_uses_the_verified_real_path_from_a_standard_directory(self):
        verified = Path("verified-root-owned/tailscale")
        with patch.object(network.Path, "is_file", return_value=True), patch.object(network.os, "access", return_value=True):
            with patch.object(network, "_trusted_file", return_value=verified) as trust:
                with patch.object(network.subprocess, "run", return_value=result({})) as execute:
                    network._run(TAILSCALE_QUERY, timeout=5)
        trust.assert_called_once_with(Path("/usr/sbin/tailscale"))
        self.assertEqual(execute.call_args.args[0], [str(verified), "status", "--json"])
        self.assertEqual(execute.call_args.kwargs["timeout"], 5)

    def test_invalid_or_offline_tailscale_state_fails_closed(self):
        cases = [None, [], {}, {"BackendState": "Stopped", "Peer": {}}, {"BackendState": "Running", "Peer": {}},
                 {"BackendState": "Running", "Peer": {"p": {"Online": False}}}]
        cases += [{"BackendState": "Running", "Peer": {"p": peer}} for peer in (
            None, {"Online": "true"}, {"Online": True, "TailscaleIPs": "100.64.0.10"},
            {"Online": True, "TailscaleIPs": []}, {"Online": True, "TailscaleIPs": ["8.8.8.8"]},
            {"Online": True, "TailscaleIPs": ["100.64.0.10;id"]},
        )]
        for peers in cases:
            with self.subTest(peers=peers):
                local = LocalNetwork(tailscale=True); local.peers = peers
                with self.assertRaises(network.NetworkError):
                    network._discover_network(runner=local.run)

    def test_controller_construction_and_status_execute_no_tools_or_discovery(self):
        with patch.object(network, "_run") as runner, patch.object(network, "_discover_network") as discover:
            with patch.object(network, "_read_json", return_value={}):
                controller = network.NetworkController("v2rayn", "unused", "unused", 10808, excluded_uids=(1500,))
                self.assertEqual(controller.status()["phase"], "stopped")
                self.assertIsNone(controller.interface)
                self.assertIsNone(controller.management_target)
                self.assertIsNone(controller.management_device)
        runner.assert_not_called(); discover.assert_not_called()

    def test_invalid_explicit_inputs_are_rejected_without_executing_tools(self):
        with patch.object(network, "_run") as runner:
            for options in ({"interface": "--help"}, {"interface": "eth9;id"}, {"management_target": "1.1.1.1"},
                            {"management_target": "100.64.0.10\nid"}, {"management_device": "tailscale0"}):
                with self.subTest(options=options), self.assertRaises(ValueError):
                    network.NetworkController("v2rayn", "unused", "unused", 10808, excluded_uids=(1500,), **options)
        runner.assert_not_called()

    def test_unsafe_route_inputs_never_reach_a_tool(self):
        runner = Mock()
        for target, device in (("10.42.0.1;id", "eth9"), ("10.42.0.1", "--help"), (True, "eth9"),
                               ("fd7a:115c:a1e0::10%eth9", "tailscale0")):
            self.assertFalse(network._management_ok(target, device, runner))
        runner.assert_not_called()

    def test_missing_tailscale_interface_does_not_accept_an_explicit_tailnet_target(self):
        with self.assertRaisesRegex(network.NetworkError, "requires tailscale0"):
            network._discover_network(management_target="100.64.0.10", runner=LocalNetwork().run)

    def test_legacy_launch_discovery_failure_precedes_guardian_state_or_network_writes(self):
        legacy = {"interface": "eth9", "management_target": "100.64.0.10", "management_device": "tailscale0"}
        with ExitStack() as stack:
            stack.enter_context(patch.object(network, "_root_platform"))
            stack.enter_context(patch.object(network, "_trusted_file", side_effect=lambda path: path))
            stack.enter_context(patch.object(network, "_read_json", return_value=legacy))
            discover = stack.enter_context(patch.object(network, "_discover_network", side_effect=network.NetworkError("ambiguous default")))
            save = stack.enter_context(patch.object(network, "_write_json"))
            runner = stack.enter_context(patch.object(network, "_run"))
            with self.assertRaisesRegex(network.NetworkError, "ambiguous default"):
                network._guard("unused", 91)
        discover.assert_called_once_with(interface="eth9", management_target="100.64.0.10", management_device="tailscale0")
        save.assert_not_called(); runner.assert_not_called()

    def test_failed_discovery_in_start_calls_no_network_mutator_or_launcher(self):
        failures = []
        for routes in ([], {}, [None], [{"dst": "default", "gateway": "10.42.0.1", "dev": "eth9"}] * 2):
            local = LocalNetwork(); local.routes = routes; failures.append(local)
        for response in (FileNotFoundError(), subprocess.TimeoutExpired(TAILSCALE_QUERY, 5), result(raw="{")):
            local = LocalNetwork(tailscale=True); local.overrides[tuple(TAILSCALE_QUERY)] = response; failures.append(local)
        for local in failures:
            with self.subTest(failure=len(failures)), ExitStack() as stack:
                stack.enter_context(patch.object(network, "_root_platform"))
                stack.enter_context(patch.object(network, "_private_directory", side_effect=lambda path: path))
                stack.enter_context(patch.object(network, "_trusted_file", side_effect=lambda path: path))
                stack.enter_context(patch.object(network, "_read_json", return_value={}))
                stack.enter_context(patch.object(network, "_take_lock", return_value=91))
                stack.enter_context(patch.object(network.os, "close"))
                stack.enter_context(patch.object(network, "_run", side_effect=local.run))
                mutators = [stack.enter_context(patch.object(network, name)) for name in ("_recover_stale", "_write_json", "_cleanup_owned")]
                launcher = stack.enter_context(patch.object(network.subprocess, "Popen"))
                controller = network.NetworkController("clash", "unused", "unused", 17897, excluded_uids=(1500,))
                with self.assertRaises(network.NetworkError):
                    controller.start()
                for operation in [*mutators, launcher]:
                    operation.assert_not_called()

    def test_preflight_checks_every_protected_route_before_kernel_reservation_queries(self):
        plan = network._discover_network(runner=LocalNetwork(tailscale=True).run)
        with patch.object(network, "socks_ready", return_value=True), patch.object(network, "_management_ok", side_effect=[True, False]) as check:
            with patch.object(network, "_rules") as rules, patch.object(network, "_run") as runner:
                with self.assertRaisesRegex(network.NetworkError, "management route"):
                    network._preflight({**plan, "socks_port": 10808})
                rules.assert_not_called(); runner.assert_not_called()
        self.assertEqual([call.args[:2] for call in check.call_args_list], [("10.42.0.1", "eth9"), ("100.64.0.10", "tailscale0")])

    def test_launch_check_schema_cannot_remove_the_lan_or_forge_tailscale_detection(self):
        plan = network._discover_network(runner=LocalNetwork(tailscale=True).run)
        for changes in ({"management_checks": plan["management_checks"][1:]}, {"tailscale": False},
                        {"management_checks": plan["management_checks"] * 2}, {"lan_gateway": "8.8.8.8"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                network._management_checks({**plan, **changes})


class GuardianDiscoveryTests(unittest.TestCase):
    def guard_loss(self, *, target, passes, tailscale=True):
        plan = network._discover_network(runner=LocalNetwork(tailscale=tailscale).run)
        marker = "fnproxy_owner_" + "a" * 24
        kernel = GuardianKernel(marker, target, passes)
        core = Mock(pid=23456); core.poll.return_value = None
        saves = []
        cleanup_owned, verify_absent = network._cleanup_owned, network._verify_absent
        workspace = REPO / "work" / "discovery-tests"
        workspace.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=workspace) as temporary, ExitStack() as stack:
            directory = Path(temporary)
            descriptor = os.open(directory / "lock", os.O_RDWR | os.O_CREAT, 0o600)
            spec = {**plan, "app": "v2rayn", "token": "a" * 24, "marker": marker,
                    "state_dir": temporary, "work_dir": temporary, "binary": "native-mihomo", "socks_port": 10808,
                    "excluded_uids": [1500], "parent_pid": 99123, "parent_start": "parent-start"}

            def launch(*_args, **_kwargs):
                kernel.tables["mihomo"] = None
                kernel.link = {"ifindex": 83}
                return core

            stack.enter_context(patch.object(network, "_root_platform"))
            stack.enter_context(patch.object(network, "_trusted_file", side_effect=lambda path: path))
            stack.enter_context(patch.object(network, "_private_directory", side_effect=lambda path: path))
            stack.enter_context(patch.object(network, "_read_json", return_value=copy.deepcopy(spec)))
            stack.enter_context(patch.object(network, "_write_json", side_effect=lambda path, data: saves.append((path.name, copy.deepcopy(data)))))
            stack.enter_context(patch.object(network, "_run", side_effect=kernel.run))
            stack.enter_context(patch.object(network, "_rules", side_effect=lambda family, runner=None: copy.deepcopy(kernel.rules[family])))
            stack.enter_context(patch.object(network, "_tables", side_effect=lambda runner=None: [{"family": "inet", "name": name} for name in kernel.tables]))
            stack.enter_context(patch.object(network, "_table_owned", side_effect=lambda name, owner, runner=None: kernel.tables.get(name) == owner))
            stack.enter_context(patch.object(network, "socks_ready", return_value=True))
            stack.enter_context(patch.object(network.socket, "socket"))
            stack.enter_context(patch.object(network, "_pid_start", return_value="start"))
            stack.enter_context(patch.object(network, "_pid_matches", side_effect=lambda pid, start: pid == 99123))
            stack.enter_context(patch.object(network, "_await_core_firewall"))
            stack.enter_context(patch.object(network, "_bridges", return_value=["docker0"]))
            stack.enter_context(patch.object(network.signal, "signal"))
            stack.enter_context(patch.object(network.time, "sleep"))
            stack.enter_context(patch.object(network.subprocess, "Popen", side_effect=launch))
            terminate = stack.enter_context(patch.object(network, "_terminate_core", side_effect=lambda state: core.poll.configure_mock(return_value=0)))
            stack.enter_context(patch.object(network, "_cleanup_owned", side_effect=lambda state: cleanup_owned(state, kernel.run)))
            stack.enter_context(patch.object(network, "_verify_absent", side_effect=lambda state: verify_absent(state, kernel.run)))
            try:
                self.assertEqual(network._guard(str(directory / "launch.json"), descriptor), 1)
            finally:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        terminate.assert_called_once()
        self.assertEqual(kernel.tables, {})
        self.assertEqual(kernel.rules, {"-4": [], "-6": []})
        self.assertIsNone(kernel.link)
        journal = [data for name, data in saves if name == "owner.json"]
        self.assertEqual(journal[-1]["phase"], "error")
        self.assertTrue(journal[-1]["cleanup_verified"])
        self.assertIn("management", journal[-1]["last_error"].lower())
        config = next(data for name, data in saves if name == "network.json")
        self.assertEqual(config["interface-name"], plan["interface"])
        self.assertEqual(config["dns"]["nameserver-policy"]["+.lan"], plan["lan_gateway"])
        self.assertEqual("+.ts.net" in config["dns"]["nameserver-policy"], tailscale)
        return journal

    def test_management_loss_after_activation_rolls_back_both_lan_and_tailnet(self):
        for target in ("10.42.0.1", "100.64.0.10"):
            with self.subTest(target=target):
                journal = self.guard_loss(target=target, passes=1)
                self.assertNotIn("active", [state["phase"] for state in journal])

    def test_runtime_management_loss_rolls_back_both_lan_and_tailnet(self):
        for target in ("10.42.0.1", "100.64.0.10"):
            with self.subTest(target=target):
                journal = self.guard_loss(target=target, passes=2)
                self.assertIn("active", [state["phase"] for state in journal])

    def test_lan_only_installation_also_rolls_back_on_runtime_route_loss(self):
        journal = self.guard_loss(target="10.42.0.1", passes=2, tailscale=False)
        self.assertIn("active", [state["phase"] for state in journal])

    def test_start_passes_the_discovered_plan_to_guardian_after_read_checks(self):
        local = LocalNetwork(tailscale=True)
        owner = {}
        launch_spec = {}
        sequence = []
        workspace = REPO / "work" / "discovery-tests"
        workspace.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=workspace) as temporary, ExitStack() as stack:
            directory = Path(temporary)
            descriptor = os.open(directory / "lock", os.O_RDWR | os.O_CREAT, 0o600)
            controller = network.NetworkController("clash", temporary, "native-mihomo", 17897, excluded_uids=(1500,), state_dir=temporary)

            def query(argv, **kwargs):
                sequence.append("read")
                return local.run(argv, **kwargs)

            def save(_path, value):
                launch_spec.update(copy.deepcopy(value))

            def launch(*_args, **_kwargs):
                owner.update(launch_spec, phase="active", guard_pid=12345, guard_start="start")
                return Mock(poll=Mock(return_value=None))

            stack.enter_context(patch.object(network, "_root_platform"))
            stack.enter_context(patch.object(network, "_private_directory", side_effect=lambda path: path))
            stack.enter_context(patch.object(network, "_trusted_file", side_effect=lambda path: path))
            stack.enter_context(patch.object(network, "_read_json", side_effect=lambda path: copy.deepcopy(owner)))
            stack.enter_context(patch.object(network, "_run", side_effect=query))
            stack.enter_context(patch.object(network, "_take_lock", return_value=descriptor))
            stack.enter_context(patch.object(network, "_pid_start", return_value="start"))
            stack.enter_context(patch.object(network, "_pid_matches", side_effect=lambda pid, start: pid == 12345))
            stack.enter_context(patch.object(network, "_recover_stale", side_effect=lambda state: sequence.append("recover")))
            stack.enter_context(patch.object(network, "_write_json", side_effect=save))
            stack.enter_context(patch.object(network.subprocess, "Popen", side_effect=launch))
            self.assertTrue(controller.start()["active"])
        self.assertEqual(launch_spec["interface"], "eth9")
        self.assertEqual(launch_spec["lan_gateway"], "10.42.0.1")
        self.assertEqual(len(launch_spec["management_checks"]), 2)
        self.assertEqual(sequence, ["read"] * 5 + ["recover"])


if __name__ == "__main__":
    unittest.main()
