"""Offline trust checks for fixed Tailscale queries and native daemon sockets."""

from contextlib import ExitStack
import importlib.util
import io
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch


REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("tailscale_native_network", REPO / "runtime" / "network.py")
network = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(network)
DISCOVERY_SPEC = importlib.util.spec_from_file_location("tailscale_discovery_fixture", REPO / "tests" / "test_network_discovery.py")
discovery = importlib.util.module_from_spec(DISCOVERY_SPEC)
DISCOVERY_SPEC.loader.exec_module(discovery)
TAILSCALE_QUERY = ["tailscale", "status", "--json"]
CUSTOM_SOCKET = "/run/vendor-tailscale/control.sock"
DAEMON = "/opt/vendor/bin/tailscaled"


def metadata(kind=stat.S_IFDIR, mode=0o755, uid=0, inode=1):
    return SimpleNamespace(st_mode=kind | mode, st_uid=uid, st_dev=7, st_ino=inode)


class TrustedTree:
    """POSIX metadata fixture with no dependence on the host user's ownership."""

    def __init__(self):
        self.entries = {}
        self.links = {}
        tree = self

        class FixturePath(PurePosixPath):
            def resolve(self, strict=False):
                value = str(self)
                for _ in range(16):
                    for source in sorted(tree.links, key=len, reverse=True):
                        if value == source or value.startswith(source + "/"):
                            value = tree.links[source] + value[len(source):]
                            break
                    else:
                        resolved = FixturePath(value)
                        if strict and value not in tree.entries:
                            raise FileNotFoundError(value)
                        return resolved
                raise OSError("Fixture symlink loop")

            def stat(self):
                return self.resolve(strict=True).lstat()

            def lstat(self):
                try:
                    return tree.entries[str(self)]
                except KeyError:
                    raise FileNotFoundError(str(self)) from None

            def is_file(self):
                try:
                    return stat.S_ISREG(self.stat().st_mode)
                except FileNotFoundError:
                    return False

        self.Path = FixturePath

    def add(self, value, *, kind=stat.S_IFDIR, mode=0o755, uid=0, inode=None):
        path = PurePosixPath(value)
        for parent in reversed(path.parents):
            self.entries.setdefault(str(parent), metadata(inode=len(self.entries) + 1))
        self.entries[value] = metadata(kind, mode, uid, inode or len(self.entries) + 1)

    def alias(self, source, destination):
        self.links[source] = destination
        self.add(source, kind=stat.S_IFLNK, mode=0o777)


def snapshot(arguments=(DAEMON.encode(), b"--socket=" + CUSTOM_SOCKET.encode())):
    return "74123", DAEMON, 7, 71, tuple(arguments)


class TailscaleToolTests(unittest.TestCase):
    def test_fixed_local_directories_use_the_existing_file_and_parent_trust_checks(self):
        for location in ("/usr/local/bin/tailscale", "/usr/local/sbin/tailscale"):
            with self.subTest(location=location):
                tree = TrustedTree()
                tree.add(location, kind=stat.S_IFREG)
                with patch.object(network, "Path", tree.Path), patch.object(network.os, "access", return_value=True):
                    self.assertEqual(network._tool("tailscale"), location)

    def test_cli_writable_file_or_any_writable_or_nonroot_parent_is_rejected(self):
        location = "/usr/local/bin/tailscale"
        for target, change in ((location, {"mode": 0o777}), (location, {"uid": 1001}),
                               ("/usr/local/bin", {"mode": 0o775}), ("/usr/local", {"uid": 1001})):
            with self.subTest(target=target, change=change):
                tree = TrustedTree()
                tree.add(location, kind=stat.S_IFREG)
                tree.add(target, kind=stat.S_IFREG if target == location else stat.S_IFDIR, **change)
                with patch.object(network, "Path", tree.Path), patch.object(network.os, "access", return_value=True):
                    with patch.object(network.subprocess, "run") as execute:
                        with self.assertRaises(network.NetworkError):
                            network._run(TAILSCALE_QUERY)
                execute.assert_not_called()

    def test_other_network_tools_do_not_gain_local_search_directories(self):
        tree = TrustedTree()
        tree.add("/usr/local/bin/ip", kind=stat.S_IFREG)
        with patch.object(network, "Path", tree.Path), patch.object(network.os, "access", return_value=True):
            with self.assertRaisesRegex(network.NetworkError, "unavailable"):
                network._tool("ip")

    def test_untrusted_earlier_cli_does_not_fall_through_to_another_installation(self):
        tree = TrustedTree()
        tree.add("/usr/bin/tailscale", kind=stat.S_IFREG, mode=0o777)
        tree.add("/usr/local/bin/tailscale", kind=stat.S_IFREG)
        with patch.object(network, "Path", tree.Path), patch.object(network.os, "access", return_value=True):
            with self.assertRaises(network.NetworkError):
                network._tool("tailscale")

    def test_local_cli_alias_executes_only_the_verified_real_file(self):
        tree = TrustedTree()
        tree.add("/opt/vendor/bin/tailscale", kind=stat.S_IFREG)
        tree.alias("/usr/local/bin/tailscale", "/opt/vendor/bin/tailscale")
        with patch.object(network, "Path", tree.Path), patch.object(network.os, "access", return_value=True):
            self.assertEqual(network._tool("tailscale"), "/opt/vendor/bin/tailscale")

    def test_only_the_fixed_read_only_tailscale_query_is_permitted(self):
        with patch.object(network.subprocess, "run") as execute, patch.object(network, "_tool") as tool:
            for argv, supplied in ((["tailscale", "up"], None),
                                   (["tailscale", "--socket=/run/other.sock", "status", "--json"], None),
                                   (TAILSCALE_QUERY, "unexpected stdin")):
                with self.subTest(argv=argv), self.assertRaises(network.NetworkError):
                    network._run(argv, input=supplied)
        execute.assert_not_called()
        tool.assert_not_called()


class SocketTrustTests(unittest.TestCase):
    def test_equal_separate_and_go_style_socket_flags_are_explicit(self):
        for flags in ((b"--socket=" + CUSTOM_SOCKET.encode(),), (b"--socket", CUSTOM_SOCKET.encode()),
                      (b"-socket=" + CUSTOM_SOCKET.encode(),), (b"-socket", CUSTOM_SOCKET.encode())):
            with self.subTest(flags=flags):
                self.assertEqual(network._tailscale_socket_argument((DAEMON.encode(), *flags)), CUSTOM_SOCKET)

    def test_standard_daemon_without_override_uses_the_standard_default(self):
        self.assertEqual(network._tailscale_socket_argument((DAEMON.encode(), b"--state=/var/lib/vendor/state")),
                         "/var/run/tailscale/tailscaled.sock")

    def test_missing_relative_duplicate_abstract_or_unbounded_socket_arguments_fail(self):
        for flags in ((b"--socket",), (b"--socket=",), (b"--socket=relative.sock",),
                      (b"--socket=@abstract",), (b"--socket=//run/control.sock",),
                      (b"--socket=/run/../tmp/control.sock",), (b"--socket=/run/control\nsock",),
                      (b"--socket=/run/" + b"x" * 108,),
                      (b"--socket=/run/a.sock", b"--socket", b"/run/b.sock")):
            with self.subTest(flags=flags), self.assertRaises(network.NetworkError):
                network._tailscale_socket_argument((DAEMON.encode(), *flags))

    def test_root_owned_real_socket_allows_socket_connect_permissions(self):
        tree = TrustedTree()
        tree.add(CUSTOM_SOCKET, kind=stat.S_IFSOCK, mode=0o666)
        with patch.object(network, "Path", tree.Path):
            self.assertEqual(str(network._trusted_socket(CUSTOM_SOCKET)), CUSTOM_SOCKET)

    def test_default_run_directory_alias_resolves_to_the_protected_real_socket(self):
        tree = TrustedTree()
        tree.add("/run/tailscale/tailscaled.sock", kind=stat.S_IFSOCK)
        tree.alias("/var/run", "/run")
        tree.add("/var/run/tailscale/tailscaled.sock", kind=stat.S_IFSOCK,
                 inode=tree.entries["/run/tailscale/tailscaled.sock"].st_ino)
        with patch.object(network, "Path", tree.Path):
            self.assertEqual(str(network._trusted_socket("/var/run/tailscale/tailscaled.sock")),
                             "/run/tailscale/tailscaled.sock")

    def test_nonroot_socket_regular_file_final_symlink_and_untrusted_parents_fail(self):
        for target, change in ((CUSTOM_SOCKET, {"kind": stat.S_IFREG}),
                               (CUSTOM_SOCKET, {"kind": stat.S_IFLNK}), (CUSTOM_SOCKET, {"uid": 1001}),
                               ("/run/vendor-tailscale", {"mode": 0o777}),
                               ("/run", {"mode": 0o1777}), ("/run/vendor-tailscale", {"uid": 1001})):
            with self.subTest(target=target, change=change):
                tree = TrustedTree()
                tree.add(CUSTOM_SOCKET, kind=stat.S_IFSOCK)
                values = {"kind": stat.S_IFSOCK if target == CUSTOM_SOCKET else stat.S_IFDIR, **change}
                tree.add(target, **values)
                with patch.object(network, "Path", tree.Path), self.assertRaises(network.NetworkError):
                    network._trusted_socket(CUSTOM_SOCKET)


class DaemonIdentityTests(unittest.TestCase):
    def process_fixture(self, stack, *, replacements=None, directory=None, exe_change=None):
        tree = TrustedTree()
        tree.add(DAEMON, kind=stat.S_IFREG, inode=71)
        files = {"comm": b"tailscaled\n", "stat": b"91 (tailscaled) S " + b"0 " * 18 + b"74123\n",
                 "status": b"Name:\ttailscaled\nUid:\t0\t0\t0\t0\n",
                 "cmdline": b"\0".join(snapshot()[4]) + b"\0"}
        files.update(replacements or {})
        if exe_change:
            tree.add(exe_change[0], **exe_change[1])
        stack.enter_context(patch.object(network, "Path", tree.Path))
        stack.enter_context(patch.object(network.os, "fstat", return_value=directory or metadata()))
        stack.enter_context(patch.object(network.os, "readlink", return_value=DAEMON))
        stack.enter_context(patch.object(network.os, "stat", return_value=tree.entries[DAEMON]))
        reader = stack.enter_context(patch.object(network, "_proc_bytes", side_effect=lambda fd, name, limit: files[name]))
        return tree, reader

    def test_root_credentials_starttime_and_actual_executable_are_bound_to_the_open_fd(self):
        with ExitStack() as stack:
            _tree, reader = self.process_fixture(stack)
            self.assertEqual(network._tailscaled_snapshot(51), snapshot())
        self.assertTrue(all(call.args[0] == 51 for call in reader.call_args_list))

    def test_running_root_daemon_can_have_native_service_acl_mask_without_exec_trust(self):
        # Named service-user ACLs appear as group-mask write bits in stat.
        # We identify the running root inode, never execute this file.
        with ExitStack() as stack:
            tree, _reader = self.process_fixture(stack)
            tree.add(DAEMON, kind=stat.S_IFREG, mode=0o775, inode=71)
            tree.add('/opt/vendor/bin', mode=0o775)
            trust=stack.enter_context(patch.object(network, '_trusted_file'))
            self.assertEqual(network._tailscaled_snapshot(51), snapshot())
        trust.assert_not_called()

    def test_running_executable_must_remain_root_regular_and_executable(self):
        for change in ({'uid':1001}, {'kind':stat.S_IFDIR}, {'mode':0o644}):
            with self.subTest(change=change),ExitStack() as stack:
                tree, _reader = self.process_fixture(stack)
                tree.add(DAEMON, kind=change.get('kind',stat.S_IFREG),
                         uid=change.get('uid',0), mode=change.get('mode',0o755), inode=71)
                with self.assertRaises(network.NetworkError):network._tailscaled_snapshot(51)

    def test_nonroot_changed_name_dead_or_bad_stat_and_bad_argv_are_rejected(self):
        cases = ({"comm": b"unrelated\n"}, {"stat": b"broken"},
                 {"stat": b"91 (tailscaled) Z " + b"0 " * 18 + b"74123\n"},
                 {"status": b"Uid:\t0\t1001\t0\t0\n"}, {"status": b"Uid:\t0\t0\t0\t0\n" * 2},
                 {"cmdline": b"tailscaled"}, {"cmdline": b"unrelated\0"})
        for replacement in cases:
            with self.subTest(replacement=replacement), ExitStack() as stack:
                self.process_fixture(stack, replacements=replacement)
                with self.assertRaises(network.NetworkError):
                    network._tailscaled_snapshot(51)
        with ExitStack() as stack:
            self.process_fixture(stack, directory=metadata(uid=1001))
            with self.assertRaises(network.NetworkError):
                network._tailscaled_snapshot(51)

    def test_running_daemon_executable_rejects_nonroot_world_write_or_missing_exec(self):
        for path, values in ((DAEMON, {"kind": stat.S_IFREG, "mode": 0o777}),
                             (DAEMON, {"kind": stat.S_IFREG, "mode": 0o644}),
                             (DAEMON, {"kind": stat.S_IFREG, "uid": 1001})):
            with self.subTest(path=path), ExitStack() as stack:
                self.process_fixture(stack, exe_change=(path, values))
                with self.assertRaises(network.NetworkError):
                    network._tailscaled_snapshot(51)

    def test_proc_executable_inode_must_match_the_verified_file(self):
        with ExitStack() as stack:
            self.process_fixture(stack)
            stack.enter_context(patch.object(network.os, "stat", return_value=metadata(stat.S_IFREG, inode=99)))
            with self.assertRaisesRegex(network.NetworkError, "executable changed"):
                network._tailscaled_snapshot(51)

    def test_process_name_alone_cannot_substitute_another_executable(self):
        for target in ("/usr/bin/python3", "relative/tailscaled", DAEMON + " (deleted)"):
            with self.subTest(target=target), ExitStack() as stack:
                self.process_fixture(stack)
                stack.enter_context(patch.object(network.os, "readlink", return_value=target))
                with self.assertRaisesRegex(network.NetworkError, "unexpected executable"):
                    network._tailscaled_snapshot(51)

    def test_bounded_proc_read_uses_relative_nofollow_fd_and_closes_it(self):
        for content, should_fail in ((b"tailscaled\n", False), (b"x" * 65, True)):
            with self.subTest(size=len(content)), ExitStack() as stack:
                stack.enter_context(patch.object(network.os, "O_CLOEXEC", 0x10000, create=True))
                stack.enter_context(patch.object(network.os, "O_NOFOLLOW", 0x20000, create=True))
                opened = stack.enter_context(patch.object(network.os, "open", return_value=52))
                source = io.BytesIO(content)
                stream = stack.enter_context(patch.object(network.os, "fdopen", return_value=source))
                if should_fail:
                    with self.assertRaisesRegex(network.NetworkError, "oversized"):
                        network._proc_bytes(51, "comm", 64)
                else:
                    self.assertEqual(network._proc_bytes(51, "comm", 64), content)
                self.assertTrue(source.closed)
                self.assertEqual(opened.call_args.kwargs, {"dir_fd": 51})
                self.assertEqual(opened.call_args.args[1] & 0x30000, 0x30000)
                stream.assert_called_once_with(52, "rb")

    @unittest.skipUnless(sys.platform == "linux", "real proc descriptors require Linux")
    def test_real_proc_read_is_bounded_and_keeps_the_process_directory_pinned(self):
        descriptor = os.open("/proc/self", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            self.assertTrue(network._proc_bytes(descriptor, "comm", 64).endswith(b"\n"))
            with self.assertRaises(network.NetworkError):
                network._proc_bytes(descriptor, "status", 1)
            os.fstat(descriptor)
        finally:
            os.close(descriptor)


class ProcessSelectionTests(unittest.TestCase):
    def scan_fixture(self, stack, names, commands, snapshots=None):
        for name, value in (("O_DIRECTORY", 0x10000), ("O_CLOEXEC", 0x20000), ("O_NOFOLLOW", 0x40000)):
            stack.enter_context(patch.object(network.os, name, value, create=True))
        entries = MagicMock()
        entries.__enter__.return_value = iter(SimpleNamespace(name=name) for name in names)
        stack.enter_context(patch.object(network.os, "scandir", return_value=entries))
        stack.enter_context(patch.object(network.os, "open", side_effect=lambda path, flags: int(path.rsplit("/", 1)[1])))
        def read(fd, _name, _limit):
            value = commands[fd]
            if isinstance(value, BaseException):
                raise value
            return value
        stack.enter_context(patch.object(network, "_proc_bytes", side_effect=read))
        identity = stack.enter_context(patch.object(network, "_tailscaled_snapshot", side_effect=snapshots,
                                                   return_value=snapshot()))
        closed = stack.enter_context(patch.object(network.os, "close"))
        return identity, closed

    def test_only_the_unique_verified_daemon_descriptor_remains_open(self):
        with ExitStack() as stack:
            identity, closed = self.scan_fixture(stack, ["self", "31", "32"], {31: b"unrelated\n", 32: b"tailscaled\n"})
            self.assertEqual(network._tailscaled_process(), (32, snapshot()))
        identity.assert_called_once_with(32)
        closed.assert_called_once_with(31)

    def test_multiple_daemons_fail_and_close_all_descriptors(self):
        with ExitStack() as stack:
            _identity, closed = self.scan_fixture(stack, ["31", "32"], {31: b"tailscaled\n", 32: b"tailscaled\n"})
            with self.assertRaisesRegex(network.NetworkError, "ambiguous"):
                network._tailscaled_process()
        self.assertEqual(sorted(call.args[0] for call in closed.call_args_list), [31, 32])

    def test_untrusted_candidate_is_not_ignored_in_favor_of_another_daemon(self):
        with ExitStack() as stack:
            _identity, closed = self.scan_fixture(stack, ["31", "32"], {31: b"tailscaled\n", 32: b"tailscaled\n"},
                                                  snapshots=[snapshot(), network.NetworkError("nonroot daemon")])
            with self.assertRaisesRegex(network.NetworkError, "nonroot"):
                network._tailscaled_process()
        self.assertEqual(sorted(call.args[0] for call in closed.call_args_list), [31, 32])

    def test_no_daemon_or_identified_daemon_disappearing_fails_closed(self):
        for command, snapshots in ((b"unrelated\n", None), (b"tailscaled\n", FileNotFoundError())):
            with self.subTest(command=command), ExitStack() as stack:
                _identity, closed = self.scan_fixture(stack, ["31"], {31: command}, snapshots=snapshots)
                with self.assertRaises(network.NetworkError):
                    network._tailscaled_process()
            closed.assert_called_once_with(31)

    def test_unrelated_exit_is_harmless_but_process_count_is_bounded(self):
        with ExitStack() as stack:
            _identity, closed = self.scan_fixture(stack, ["31", "32"], {31: FileNotFoundError(), 32: b"tailscaled\n"})
            self.assertEqual(network._tailscaled_process()[0], 32)
        closed.assert_called_once_with(31)
        with ExitStack() as stack:
            self.scan_fixture(stack, ["31", "32"], {31: b"unrelated\n", 32: b"tailscaled\n"})
            stack.enter_context(patch.object(network, "_DISCOVERY_MAX_ROWS", 1))
            with self.assertRaisesRegex(network.NetworkError, "safe bound"):
                network._tailscaled_process()

    def test_process_discovery_has_a_time_bound(self):
        with ExitStack() as stack:
            self.scan_fixture(stack, ["31"], {31: b"tailscaled\n"})
            stack.enter_context(patch.object(network.time, "monotonic", side_effect=[0, 6]))
            with self.assertRaisesRegex(network.NetworkError, "safe bound"):
                network._tailscaled_process()


class StatusQueryTests(unittest.TestCase):
    def query_fixture(self, stack, *, identity=None, path=CUSTOM_SOCKET):
        tree = TrustedTree()
        tree.add(path, kind=stat.S_IFSOCK, inode=81)
        stack.enter_context(patch.object(network.sys, "platform", "linux"))
        stack.enter_context(patch.object(network.os, "geteuid", return_value=0, create=True))
        stack.enter_context(patch.object(network, "Path", tree.Path))
        stack.enter_context(patch.object(network, "_tool", return_value="/usr/local/bin/tailscale"))
        stack.enter_context(patch.object(network, "_tailscaled_process", return_value=(51, identity or snapshot())))
        checked = stack.enter_context(patch.object(network, "_tailscaled_snapshot", return_value=identity or snapshot()))
        closed = stack.enter_context(patch.object(network.os, "close"))
        execute = stack.enter_context(patch.object(network.subprocess, "run",
                                                  return_value=subprocess.CompletedProcess([], 0, "{}", "")))
        return tree, execute, checked, closed

    def test_custom_socket_query_has_fixed_argv_and_is_rechecked_after_execution(self):
        with ExitStack() as stack:
            _tree, execute, checked, closed = self.query_fixture(stack)
            self.assertEqual(network._run(TAILSCALE_QUERY, timeout=5).stdout, "{}")
        self.assertEqual(execute.call_args.args[0], ["/usr/local/bin/tailscale", "--socket=" + CUSTOM_SOCKET, "status", "--json"])
        self.assertEqual(execute.call_args.kwargs, {"text": True, "capture_output": True, "timeout": 5, "check": False})
        self.assertEqual(checked.call_count, 2)
        closed.assert_called_once_with(51)

    def test_standard_daemon_uses_the_validated_default_socket(self):
        default = "/var/run/tailscale/tailscaled.sock"
        identity = snapshot((DAEMON.encode(),))
        with ExitStack() as stack:
            _tree, execute, _checked, closed = self.query_fixture(stack, identity=identity, path=default)
            network._run(TAILSCALE_QUERY)
        self.assertEqual(execute.call_args.args[0], ["/usr/local/bin/tailscale", "--socket=" + default, "status", "--json"])
        closed.assert_called_once_with(51)

    def test_identity_change_before_query_prevents_execution_and_closes_descriptor(self):
        with ExitStack() as stack:
            _tree, execute, checked, closed = self.query_fixture(stack)
            checked.return_value = ("74124", *snapshot()[1:])
            with self.assertRaisesRegex(network.NetworkError, "before status"):
                network._run(TAILSCALE_QUERY)
        execute.assert_not_called()
        closed.assert_called_once_with(51)

    def test_identity_change_during_query_discards_the_result(self):
        with ExitStack() as stack:
            _tree, execute, checked, closed = self.query_fixture(stack)
            checked.side_effect = [snapshot(), ("74124", *snapshot()[1:])]
            with self.assertRaisesRegex(network.NetworkError, "during status"):
                network._run(TAILSCALE_QUERY)
        execute.assert_called_once()
        closed.assert_called_once_with(51)

    def test_socket_replacement_during_query_discards_the_result(self):
        with ExitStack() as stack:
            tree, execute, _checked, closed = self.query_fixture(stack)
            def replace(_argv, **_kwargs):
                tree.add(CUSTOM_SOCKET, kind=stat.S_IFSOCK, inode=82)
                return subprocess.CompletedProcess([], 0, "{}", "")
            execute.side_effect = replace
            with self.assertRaisesRegex(network.NetworkError, "during status"):
                network._run(TAILSCALE_QUERY)
        closed.assert_called_once_with(51)

    def test_unsafe_custom_socket_never_falls_back_to_a_default(self):
        with ExitStack() as stack:
            tree, execute, _checked, closed = self.query_fixture(stack)
            tree.add(CUSTOM_SOCKET, kind=stat.S_IFSOCK, uid=1001)
            tree.add("/var/run/tailscale/tailscaled.sock", kind=stat.S_IFSOCK)
            with self.assertRaises(network.NetworkError):
                network._run(TAILSCALE_QUERY)
        execute.assert_not_called()
        closed.assert_called_once_with(51)

    def test_failed_or_timed_out_queries_close_the_pinned_descriptor(self):
        for failure in (subprocess.TimeoutExpired(TAILSCALE_QUERY, 5), OSError("query unavailable"),
                        subprocess.CompletedProcess([], 1, "", "daemon offline")):
            with self.subTest(failure=type(failure).__name__), ExitStack() as stack:
                _tree, execute, _checked, closed = self.query_fixture(stack)
                if isinstance(failure, BaseException):
                    execute.side_effect = failure
                else:
                    execute.return_value = failure
                with self.assertRaises((network.NetworkError, OSError, subprocess.SubprocessError)):
                    network._run(TAILSCALE_QUERY)
            closed.assert_called_once_with(51)

    def test_cli_and_process_discovery_are_not_used_without_tailscale0(self):
        local = discovery.LocalNetwork()
        with patch.object(network, "_tailscaled_process") as process, patch.object(network.subprocess, "run") as execute:
            self.assertFalse(network._discover_network(runner=local.run)["tailscale"])
        process.assert_not_called()
        execute.assert_not_called()

    def test_failed_native_socket_discovery_precedes_every_start_mutator(self):
        local = discovery.LocalNetwork(tailscale=True)
        real_run = network._run
        def query(argv, **kwargs):
            return real_run(argv, **kwargs) if argv[0] == "tailscale" else local.run(argv, **kwargs)
        with ExitStack() as stack:
            stack.enter_context(patch.object(network.sys, "platform", "linux"))
            stack.enter_context(patch.object(network.os, "geteuid", return_value=0, create=True))
            stack.enter_context(patch.object(network, "_root_platform"))
            stack.enter_context(patch.object(network, "_private_directory", side_effect=lambda path: path))
            stack.enter_context(patch.object(network, "_trusted_file", side_effect=lambda path: path))
            stack.enter_context(patch.object(network, "_read_json", return_value={}))
            stack.enter_context(patch.object(network, "_tool", return_value="/usr/local/bin/tailscale"))
            stack.enter_context(patch.object(network, "_take_lock", return_value=91))
            stack.enter_context(patch.object(network.os, "close"))
            stack.enter_context(patch.object(network, "_run", side_effect=query))
            stack.enter_context(patch.object(network, "_tailscaled_process", side_effect=network.NetworkError("ambiguous daemon")))
            mutators = [stack.enter_context(patch.object(network, name))
                        for name in ("_recover_stale", "_write_json", "_cleanup_owned")]
            launch = stack.enter_context(patch.object(network.subprocess, "Popen"))
            execute = stack.enter_context(patch.object(network.subprocess, "run"))
            controller = network.NetworkController("clash", "unused", "unused", 17897, excluded_uids=(1500,))
            with self.assertRaisesRegex(network.NetworkError, "Tailscale CLI"):
                controller.start()
            for operation in [*mutators, launch, execute]:
                operation.assert_not_called()


if __name__ == "__main__":
    unittest.main()
