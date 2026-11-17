"""Privileged native forwarding to a desktop client's loopback SOCKS port.

The desktop stays unprivileged.  A separate guardian owns the lease and the
Mihomo child, checks the management route, and rolls back on parent/client
failure.  No node credentials or subscription is stored here.
"""

from __future__ import annotations

import ctypes
from contextlib import contextmanager
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import time
from typing import Any, Callable, Iterable

try:
    import fcntl
except ImportError:  # Configuration generation and portable unit tests.
    fcntl = None


STATE_DIR = Path("/run/fnos-native-proxy-network")
DEVICE = "fnproxy0"
TABLE = 2099
RULE_INDEX = 19000
INPUT_MARK = 0x2099
OUTPUT_MARK = 0x209A
DNS_PORT = 15353
DNS_TABLE = "fnproxy_dns"
_APPS = {"v2rayn", "clash"}
_BYPASS4 = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
            "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4")
_FAKE6_POOL = ipaddress.ip_network("fdfe:dcba:9876::/64")
# Keep other ULA traffic direct without bypassing synthetic AAAA destinations.
_BYPASS6 = ("::/128", "::1/128",
            *(str(subnet) for subnet in ipaddress.ip_network("fc00::/7").address_exclude(_FAKE6_POOL)),
            "fe80::/10", "ff00::/8")
_DIRECT_PROCESSES = ("tailscaled", "v2rayN", "xray", "sing-box", "mihomo",
                     "verge-mihomo", "verge-mihomo-alpha", "clash-verge")
_RESERVED_PRIORITIES = {2, 4, 5, *range(RULE_INDEX, RULE_INDEX + 11), 32768}
_LAN_NETWORKS = tuple(ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
_TAILNET_NETWORKS = (ipaddress.ip_network("100.64.0.0/10"), ipaddress.ip_network("fd7a:115c:a1e0::/48"))
_DISCOVERY_TIMEOUT = 5
_DISCOVERY_MAX_BYTES = 2 * 1024 * 1024
_DISCOVERY_MAX_ROWS = 4096


class NetworkError(RuntimeError):
    pass


class NetworkBusy(NetworkError):
    pass


def _uids(values: Iterable[int]) -> list[int]:
    supplied = list(values)
    if len(supplied) > 64 or any(isinstance(v, bool) or not isinstance(v, int) or not 0 < v < 2**32 - 1 for v in supplied):
        raise ValueError("GUI exclusions must be non-root numeric user IDs")
    return sorted(set(supplied))


def _interface(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}", value):
        raise ValueError("Invalid network interface")
    return value


def _lan_gateway(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("The LAN gateway must be an IPv4 RFC1918 address")
    address = ipaddress.ip_address(value)
    if address.version != 4 or not any(address in subnet for subnet in _LAN_NETWORKS):
        raise ValueError("The LAN gateway must be an IPv4 RFC1918 address")
    return str(address)


def _management_address(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("Management checks require a LAN or Tailscale IP address")
    address = ipaddress.ip_address(value)
    if getattr(address, "scope_id", None) is not None:
        raise ValueError("Scoped management IP addresses are not supported")
    if not any(address.version == subnet.version and address in subnet
               for subnet in (*_LAN_NETWORKS, *_TAILNET_NETWORKS)):
        raise ValueError("Management checks require a LAN or Tailscale IP address")
    return str(address)


def _tailnet_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return any(address.version == subnet.version and address in subnet for subnet in _TAILNET_NETWORKS)


def build_config(socks_port: int, *, excluded_uids: Iterable[int], interface: str | None = None,
                 lan_gateway: str | None = None, tailscale: bool = False) -> dict[str, Any]:
    """JSON is a YAML subset accepted by Mihomo. All rules are local/static.

    The inline address provider enables auto-redirect *mark mode*. Dedicated
    mark-only policy rules can then precede fnOS's existing priority-10 source
    rule, without altering that rule or unmarked LAN/management traffic.
    """
    if isinstance(socks_port, bool) or not isinstance(socks_port, int) or not 1024 <= socks_port <= 65535:
        raise ValueError("Invalid loopback SOCKS port")
    excluded = _uids(excluded_uids)
    if not excluded:
        raise ValueError("GUI user exclusions are required to prevent proxy recursion")
    # Mihomo's nftables interval set needs adjacent UID exclusions coalesced.
    uid_ranges = [[excluded[0], excluded[0]]]
    for uid in excluded[1:]:
        if uid == uid_ranges[-1][1] + 1:
            uid_ranges[-1][1] = uid
        else:
            uid_ranges.append([uid, uid])
    if interface is not None:
        interface = _interface(interface)
    if lan_gateway is not None:
        lan_gateway = _lan_gateway(lan_gateway)
    if not isinstance(tailscale, bool):
        raise ValueError("Tailscale detection must be a boolean")
    local_dns = lan_gateway or "system"
    dns_policy = {"+.lan": local_dns, "+.local": local_dns}
    if tailscale:
        dns_policy["+.ts.net"] = "100.100.100.100"
    rules = [f"PROCESS-NAME,{name},DIRECT" for name in _DIRECT_PROCESSES]
    rules += [f"IP-CIDR,{subnet},DIRECT,no-resolve" for subnet in _BYPASS4]
    rules += [f"IP-CIDR6,{subnet},DIRECT,no-resolve" for subnet in _BYPASS6]
    rules += ["DOMAIN-SUFFIX,ts.net,DIRECT", "DOMAIN-SUFFIX,lan,DIRECT",
              "DOMAIN-SUFFIX,local,DIRECT", "MATCH,LOCAL-CLIENT"]
    configuration = {
        "mode": "rule", "log-level": "warning", "ipv6": True,
        "find-process-mode": "always",
        "allow-lan": False, "port": 0, "socks-port": 0, "mixed-port": 0,
        "external-controller": "", "external-ui": "",
        "profile": {"store-selected": False, "store-fake-ip": False},
        "tun": {
            "enable": True, "device": DEVICE, "stack": "mixed", "mtu": 1500,
            "auto-route": True, "auto-redirect": True, "auto-detect-interface": interface is None,
            "strict-route": False, "dns-mode": "disabled",
            "dns-hijack": ["any:53", "tcp://any:53"],
            "inet6-address": ["fdfe:dcba:2099::1/126"],
            "iproute2-table-index": TABLE, "iproute2-rule-index": RULE_INDEX,
            "auto-redirect-input-mark": INPUT_MARK, "auto-redirect-output-mark": OUTPUT_MARK,
            "auto-redirect-iproute2-fallback-rule-index": 32768,
            "route-address-set": ["fnproxy-all-addresses"],
            "route-exclude-address": [*_BYPASS4, *_BYPASS6],
            "exclude-interface": ["tailscale0"],
            "exclude-uid-range": [f"{first}:{last}" for first, last in uid_ranges],
        },
        "rule-providers": {
            "fnproxy-all-addresses": {"type": "inline", "behavior": "ipcidr", "format": "text",
                                      "payload": ["0.0.0.0/0", "::/0"]}
        },
        "dns": {
            "enable": True, "listen": f"[::]:{DNS_PORT}", "ipv6": True,
            "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
            "fake-ip-range6": str(_FAKE6_POOL),
            "fake-ip-filter": ["*.lan", "*.local", "+.ts.net", "localhost", "*.in-addr.arpa", "*.ip6.arpa"],
            "use-hosts": True, "use-system-hosts": True, "respect-rules": False,
            "default-nameserver": ["223.5.5.5", "119.29.29.29"],
            "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
            "direct-nameserver": ["223.5.5.5", "119.29.29.29"],
            "nameserver": ["https://1.1.1.1/dns-query#LOCAL-CLIENT", "https://8.8.8.8/dns-query#LOCAL-CLIENT"],
            "nameserver-policy": dns_policy,
        },
        "proxies": [{"name": "LOCAL-CLIENT", "type": "socks5", "server": "127.0.0.1",
                     "port": socks_port, "udp": True}],
        "proxy-groups": [], "rules": rules,
    }
    if interface is not None:
        configuration["interface-name"] = interface
    return configuration


def _tool(name: str) -> str:
    prefixes = ("/usr/sbin", "/sbin", "/usr/bin", "/bin")
    if name == "tailscale":
        prefixes += ("/usr/local/bin", "/usr/local/sbin")
    for prefix in prefixes:
        candidate = Path(prefix) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            # Tailscale is queried by the privileged guardian. Resolve the
            # selected standard-directory entry and verify its real file and
            # ancestor ownership before executing it as root.
            return str(_trusted_file(candidate) if name == "tailscale" else candidate)
    raise NetworkError("Required network tool is unavailable: " + name)


def _run(argv: list[str], *, input: str | None = None, check: bool = True, timeout: float = 10) -> subprocess.CompletedProcess[str]:
    if argv[0] == "tailscale":
        if argv != ["tailscale", "status", "--json"] or input is not None:
            raise NetworkError("Only the fixed read-only Tailscale status query is supported")
        with _tailscale_status_command(_tool("tailscale")) as command:
            result = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    else:
        command = [_tool(argv[0]), *argv[1:]] if argv[0] in ("ip", "nft") else argv
        result = subprocess.run(command, input=input, text=True, capture_output=True, timeout=timeout, check=False)
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip()[-1200:]
        raise NetworkError(f"{argv[0]} operation failed: {detail}")
    return result


def _root_platform() -> None:
    if sys.platform != "linux" or fcntl is None or os.geteuid() != 0:
        raise NetworkError("Network control requires the root native Linux supervisor")


def _private_directory(path: Path) -> Path:
    if path.is_symlink():
        raise NetworkError("Network control directory must not be a symlink")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    metadata = path.stat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077:
        raise NetworkError("Network control directory must be root-owned with mode 0700")
    return path.resolve()


def _trusted_file(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise NetworkError("Network executable must be a root-owned, non-writable regular file")
    for parent in resolved.parents:
        parent_meta = parent.stat()
        if parent_meta.st_uid != 0 or parent_meta.st_mode & 0o022:
            raise NetworkError("Network executable has an untrusted parent directory")
    return resolved


def _proc_bytes(descriptor: int, name: str, limit: int) -> bytes:
    """Read a bounded proc file relative to the already opened process."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    with os.fdopen(os.open(name, flags, dir_fd=descriptor), "rb") as source:
        value = source.read(limit + 1)
    if len(value) > limit:
        raise NetworkError("Tailscale process metadata is oversized")
    return value


def _tailscaled_snapshot(descriptor: int) -> tuple[str, str, int, int, tuple[bytes, ...]]:
    """Bind root credentials, argv and executable to one pinned /proc entry."""
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise NetworkError("Tailscale daemon must be root-owned")
    if _proc_bytes(descriptor, "comm", 64) != b"tailscaled\n":
        raise NetworkError("Tailscale daemon identity changed")
    fields = _proc_bytes(descriptor, "stat", 4096).rsplit(b") ", 1)[-1].split()
    if len(fields) < 20 or fields[0] in (b"Z", b"X") or not fields[19].isdigit():
        raise NetworkError("Tailscale daemon has invalid process identity")
    uids = [line.split()[1:] for line in _proc_bytes(descriptor, "status", 16384).splitlines()
            if line.startswith(b"Uid:")]
    if uids != [[b"0", b"0", b"0", b"0"]]:
        raise NetworkError("Tailscale daemon must retain root credentials")
    target = os.readlink("exe", dir_fd=descriptor)
    if not PurePosixPath(target).is_absolute() or PurePosixPath(target).name != "tailscaled":
        raise NetworkError("Tailscale daemon has an unexpected executable")
    # This identifies an already-running root process; this path is never
    # executed by us. Native app packages can grant their service user an ACL
    # on their binaries. Keep the strict _trusted_file rule for the CLI we do
    # execute, and bind this running daemon to its actual root-owned inode.
    executable = Path(target).resolve(strict=True)
    real_meta, running_meta = executable.stat(), os.stat("exe", dir_fd=descriptor)
    if (not stat.S_ISREG(real_meta.st_mode) or not stat.S_ISREG(running_meta.st_mode)
            or real_meta.st_uid != 0 or running_meta.st_uid != 0
            or real_meta.st_mode & 0o002
            or not real_meta.st_mode & 0o111
            or (real_meta.st_dev, real_meta.st_ino) != (running_meta.st_dev, running_meta.st_ino)):
        raise NetworkError("Tailscale daemon executable changed")
    command = _proc_bytes(descriptor, "cmdline", 65536)
    if not command.endswith(b"\0"):
        raise NetworkError("Tailscale daemon has invalid arguments")
    arguments = tuple(command[:-1].split(b"\0"))
    if not arguments[0] or PurePosixPath(os.fsdecode(arguments[0])).name != "tailscaled":
        raise NetworkError("Tailscale daemon has invalid arguments")
    return fields[19].decode("ascii"), str(executable), real_meta.st_dev, real_meta.st_ino, arguments


def _tailscaled_process() -> tuple[int, tuple[str, str, int, int, tuple[bytes, ...]]]:
    """Keep only one verified daemon; never infer a socket from user processes."""
    selected = None
    snapshot = None
    count = 0
    deadline = time.monotonic() + _DISCOVERY_TIMEOUT
    try:
        with os.scandir("/proc") as entries:
            for entry in entries:
                if not re.fullmatch(r"[1-9][0-9]*", entry.name):
                    continue
                count += 1
                if count > _DISCOVERY_MAX_ROWS or time.monotonic() > deadline:
                    raise NetworkError("Tailscale process discovery exceeded its safe bound")
                descriptor = None
                identified = False
                try:
                    descriptor = os.open("/proc/" + entry.name,
                                         os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
                    if _proc_bytes(descriptor, "comm", 64) != b"tailscaled\n":
                        continue
                    identified = True
                    current = _tailscaled_snapshot(descriptor)
                    if selected is not None:
                        raise NetworkError("Multiple Tailscale daemons are ambiguous")
                    selected, snapshot = descriptor, current
                    descriptor = None
                except (FileNotFoundError, ProcessLookupError):
                    # An unrelated process can exit during the scan. Once it
                    # identifies as tailscaled, disappearance is a failed check.
                    if identified:
                        raise NetworkError("Tailscale daemon disappeared during discovery")
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
        if selected is None:
            raise NetworkError("Cannot identify one trusted root Tailscale daemon")
        return selected, snapshot
    except BaseException:
        if selected is not None:
            os.close(selected)
        raise


def _tailscale_socket_argument(arguments: tuple[bytes, ...]) -> str:
    supplied = []
    index = 1
    while index < len(arguments):
        value = arguments[index]
        if value in (b"--socket", b"-socket"):
            index += 1
            if index >= len(arguments):
                raise NetworkError("Tailscale socket argument is missing")
            supplied.append(os.fsdecode(arguments[index]))
        elif value.startswith((b"--socket=", b"-socket=")):
            supplied.append(os.fsdecode(value.split(b"=", 1)[1]))
        index += 1
    if len(supplied) > 1:
        raise NetworkError("Tailscale socket arguments are ambiguous")
    value = supplied[0] if supplied else "/var/run/tailscale/tailscaled.sock"
    if (not PurePosixPath(value).is_absolute() or value.startswith("//")
            or ".." in value.split("/") or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or len(os.fsencode(value)) > 107):
        raise NetworkError("Tailscale requires a bounded absolute Unix socket path")
    return value


def _trusted_socket(value: str) -> Path:
    candidate = Path(value)
    metadata = candidate.lstat()
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != 0:
        raise NetworkError("Tailscale socket must be a root-owned real Unix socket")
    resolved = candidate.resolve(strict=True)
    real_meta = resolved.lstat()
    if (metadata.st_dev, metadata.st_ino) != (real_meta.st_dev, real_meta.st_ino):
        raise NetworkError("Tailscale socket changed during discovery")
    for parent in resolved.parents:
        parent_meta = parent.stat()
        if (not stat.S_ISDIR(parent_meta.st_mode) or parent_meta.st_uid != 0
                or parent_meta.st_mode & 0o022):
            raise NetworkError("Tailscale socket has an untrusted parent directory")
    return resolved


@contextmanager
def _tailscale_status_command(executable: str):
    # Actual network control is root Linux only. Keep portable configuration
    # tests and nonprivileged CLI callers independent of Linux /proc details.
    if sys.platform != "linux" or os.geteuid() != 0:
        yield [executable, "status", "--json"]
        return
    descriptor, snapshot = _tailscaled_process()
    try:
        value = _tailscale_socket_argument(snapshot[4])
        path = _trusted_socket(value)
        metadata = path.stat()
        if _tailscaled_snapshot(descriptor) != snapshot:
            raise NetworkError("Tailscale daemon identity changed before status query")
        yield [executable, "--socket=" + str(path), "status", "--json"]
        verified = _trusted_socket(value)
        current = verified.stat()
        if (verified != path or (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino)
                or _tailscaled_snapshot(descriptor) != snapshot):
            raise NetworkError("Tailscale daemon or socket changed during status query")
    finally:
        os.close(descriptor)


def _write_json(path: Path, content: dict[str, Any]) -> None:
    if path.is_symlink():
        raise NetworkError("Refusing to replace a symlink in network state")
    temporary = path.with_name(path.name + "." + secrets.token_hex(6) + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(content, output, indent=2)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    if path.is_symlink() or not path.is_file():
        raise NetworkError("Invalid network state file")
    return json.loads(path.read_text(encoding="utf-8"))


def _pid_start(pid: int) -> str | None:
    try:
        # comm can contain spaces and parentheses, so split after its last ')'.
        fields = Path(f"/proc/{int(pid)}/stat").read_text().rsplit(") ", 1)[1].split()
        return None if fields[0] == "Z" else fields[19]
    except (OSError, ValueError, IndexError):
        return None


def _pid_matches(pid: Any, start: Any) -> bool:
    return isinstance(pid, int) and pid > 1 and isinstance(start, str) and _pid_start(pid) == start


def socks_ready(port: int, timeout: float = 1.0) -> bool:
    """Require a SOCKS5 no-auth handshake, not merely an open TCP listener."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            connection.sendall(b"\x05\x01\x00")
            response = b""
            while len(response) < 2:
                chunk = connection.recv(2 - len(response))
                if not chunk:
                    return False
                response += chunk
            return response == b"\x05\x00"
    except OSError:
        return False


def _discovery_json(argv: list[str], runner: Callable[..., Any] | None = None) -> Any:
    """Read fixed local-tool queries with bounded time, output and JSON shape."""
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON property")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise ValueError("Non-finite JSON value")

    try:
        result = (runner or _run)(argv, timeout=_DISCOVERY_TIMEOUT)
        if result.returncode or not isinstance(result.stdout, str) or len(result.stdout) > _DISCOVERY_MAX_BYTES:
            raise ValueError("Failed or oversized local discovery response")
        if len(result.stdout.encode("utf-8")) > _DISCOVERY_MAX_BYTES:
            raise ValueError("Oversized local discovery response")
        return json.loads(result.stdout, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (NetworkError, OSError, ValueError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        if argv[0] == "tailscale":
            raise NetworkError("tailscale0 存在，但找不到可用的受信系统 Tailscale CLI，或无法取得有效状态；网络接管未启动") from error
        raise NetworkError("Cannot safely discover local network state using " + argv[0]) from error


def _management_checks(spec: dict[str, Any]) -> list[dict[str, str]]:
    """Validate new launch plans and explicitly supplied legacy check fields."""
    supplied = spec.get("management_checks")
    if supplied is None:
        # Legacy journals can still be read/recovered. A legacy launch is
        # rediscovered in _guard before any resources can be claimed.
        supplied = [{"target": spec.get("management_target"), "device": spec.get("management_device")}]
    if not isinstance(supplied, list) or not 1 <= len(supplied) <= 4:
        raise ValueError("Invalid management check list")
    checks = []
    for item in supplied:
        if not isinstance(item, dict) or set(item) != {"target", "device"}:
            raise ValueError("Invalid management check")
        check = {"target": _management_address(item["target"]), "device": _interface(item["device"])}
        if check["device"] in ("lo", DEVICE) or _tailnet_address(check["target"]) != (check["device"] == "tailscale0"):
            raise ValueError("Management target and protected device do not match")
        if check in checks:
            raise ValueError("Duplicate management check")
        checks.append(check)
    if "management_checks" in spec:
        lan = {"target": _lan_gateway(spec.get("lan_gateway")), "device": _interface(spec.get("interface"))}
        if lan not in checks or not isinstance(spec.get("tailscale"), bool):
            raise ValueError("A discovered LAN management check is required")
        has_tailnet = any(check["device"] == "tailscale0" for check in checks)
        if spec["tailscale"] != has_tailnet:
            raise ValueError("Tailscale discovery and management checks do not match")
    return checks


def _management_ok(target: str, expected_device: str, runner: Callable[..., Any] | None = None) -> bool:
    try:
        target = _management_address(target)
        expected_device = _interface(expected_device)
        family = ["-6"] if ipaddress.ip_address(target).version == 6 else []
        rows = _discovery_json(["ip", *family, "-j", "route", "get", target], runner)
        return (isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict)
                and rows[0].get("dev") == expected_device and rows[0].get("type", "unicast") == "unicast")
    except (NetworkError, OSError, ValueError, TypeError, subprocess.SubprocessError):
        return False


def _management_routes_ok(spec: dict[str, Any], runner: Callable[..., Any] | None = None) -> bool:
    try:
        return all(_management_ok(check["target"], check["device"], runner) for check in _management_checks(spec))
    except (ValueError, TypeError):
        return False


def _discover_network(*, interface: str | None = None, management_target: str | None = None,
                      management_device: str | None = None, runner: Callable[..., Any] | None = None) -> dict[str, Any]:
    """Select only a uniquely identified main-table LAN and optional tailnet.

    No rule, firewall, interface or service is changed here. An explicit
    interface may resolve multiple default exits but must still have exactly
    one ordinary IPv4 default route with an RFC1918 gateway.
    """
    try:
        if interface is not None:
            interface = _interface(interface)
        if management_target is not None:
            management_target = _management_address(management_target)
        if management_device is not None:
            management_device = _interface(management_device)
            if management_target is None:
                raise ValueError("A management device override requires a target")
        routes = _discovery_json(["ip", "-4", "-j", "route", "show", "table", "main", "default"], runner)
        if not isinstance(routes, list) or not 1 <= len(routes) <= _DISCOVERY_MAX_ROWS:
            raise ValueError("No safe IPv4 default route in table main")
        candidates = []
        for row in routes:
            if (not isinstance(row, dict) or row.get("dst") not in ("default", "0.0.0.0/0")
                    or row.get("table", "main") not in ("main", 254)
                    or row.get("type", "unicast") != "unicast" or "nexthops" in row or "nhid" in row):
                raise ValueError("Unsupported main-table default route")
            device = _interface(row.get("dev"))
            gateway = _lan_gateway(row.get("gateway"))
            flags = row.get("flags", [])
            if (device in ("lo", "tailscale0", DEVICE) or not isinstance(flags, list)
                    or any(not isinstance(flag, str) for flag in flags) or {"dead", "linkdown"}.intersection(flags)):
                raise ValueError("The default route does not have a usable LAN interface")
            if interface is None or device == interface:
                candidates.append((device, gateway))
        if len(candidates) != 1:
            raise ValueError("The IPv4 default route is missing or ambiguous; specify a unique LAN interface")
        selected, gateway = candidates[0]
        rows = _discovery_json(["ip", "-j", "link", "show"], runner)
        if not isinstance(rows, list) or not 1 <= len(rows) <= _DISCOVERY_MAX_ROWS:
            raise ValueError("Invalid interface inventory")
        links = {}
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("Invalid interface inventory")
            name = _interface(row.get("ifname"))
            flags = row.get("flags")
            if name in links or not isinstance(flags, list) or any(not isinstance(flag, str) for flag in flags):
                raise ValueError("Invalid or repeated interface inventory")
            links[name] = flags
        if selected not in links or "UP" not in links[selected]:
            raise ValueError("The selected LAN interface is not up")
        checks = [{"target": gateway, "device": selected}]
        has_tailnet = "tailscale0" in links
        if has_tailnet:
            if "UP" not in links["tailscale0"]:
                raise ValueError("The Tailscale management interface is not up")
            data = _discovery_json(["tailscale", "status", "--json"], runner)
            if not isinstance(data, dict) or data.get("BackendState") != "Running" or not isinstance(data.get("Peer"), dict):
                raise ValueError("Tailscale must be running with an online peer before takeover")
            if len(data["Peer"]) > _DISCOVERY_MAX_ROWS:
                raise ValueError("The Tailscale peer inventory is too large")
            targets = set()
            for peer in data["Peer"].values():
                if not isinstance(peer, dict) or not isinstance(peer.get("Online", False), bool):
                    raise ValueError("Invalid Tailscale peer inventory")
                if peer.get("Online") is not True:
                    continue
                addresses = peer.get("TailscaleIPs")
                if not isinstance(addresses, list) or not 1 <= len(addresses) <= 16:
                    raise ValueError("Invalid online Tailscale peer addresses")
                for address in addresses:
                    target = _management_address(address)
                    if not _tailnet_address(target):
                        raise ValueError("An online Tailscale peer contains a non-tailnet address")
                    targets.add(target)
            if not targets:
                raise ValueError("No online Tailscale peer is available for management protection")
            if management_target is not None and _tailnet_address(management_target):
                if management_target not in targets or management_device not in (None, "tailscale0"):
                    raise ValueError("The explicit Tailscale target is not an online peer on tailscale0")
                tailnet_target = management_target
            else:
                tailnet_target = min(targets, key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))))
            checks.append({"target": tailnet_target, "device": "tailscale0"})
        elif management_target is not None and _tailnet_address(management_target):
            raise ValueError("An explicit Tailscale management target requires tailscale0")
        if management_target is not None and not _tailnet_address(management_target):
            if management_device not in (None, selected):
                raise ValueError("An explicit LAN management target must use the selected LAN interface")
            check = {"target": management_target, "device": selected}
            if check not in checks:
                checks.append(check)
        # Keep the legacy pair for readable existing state, but the guardian
        # validates and checks every entry in management_checks.
        primary = checks[1] if has_tailnet else checks[0]
        plan = {"interface": selected, "lan_gateway": gateway, "tailscale": has_tailnet,
                "management_checks": checks, "management_target": primary["target"], "management_device": primary["device"]}
        if not _management_routes_ok(plan, runner):
            raise ValueError("LAN or Tailscale management routing is not intact")
        return plan
    except (ValueError, TypeError, KeyError, RecursionError) as error:
        raise NetworkError("Cannot safely select management networking: " + str(error)) from error


def _rules(family: str, runner: Callable[..., Any] = _run) -> list[dict[str, Any]]:
    return json.loads(runner(["ip", family, "-j", "rule", "show"]).stdout)


def _tables(runner: Callable[..., Any] = _run) -> list[dict[str, Any]]:
    data = json.loads(runner(["nft", "-j", "list", "tables"]).stdout)
    return [entry["table"] for entry in data.get("nftables", []) if "table" in entry]


def _has_table(name: str, runner: Callable[..., Any] = _run) -> bool:
    return any(table.get("family") == "inet" and table.get("name") == name for table in _tables(runner))


def _table_owned(name: str, marker: str, runner: Callable[..., Any] = _run) -> bool:
    if not re.fullmatch(r"fnproxy_owner_[0-9a-f]{24}", marker):
        return False
    result = runner(["nft", "-j", "list", "table", "inet", name], check=False)
    if result.returncode:
        return False
    data = json.loads(result.stdout)
    return any(entry.get("chain", {}).get("name") == marker
               and entry["chain"].get("table") == name
               and entry["chain"].get("family") == "inet" for entry in data.get("nftables", []))


def _await_core_firewall(marker: str, core: Any, stopped: Callable[[], bool], *, timeout: float = 12) -> None:
    """sing-tun flushes address sets before publishing redirect chains."""
    expected = {"output", "output_udp_icmp", "prerouting", "prerouting_udp_icmp"}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if stopped() or core.poll() is not None:
            raise NetworkError("Forwarding core stopped before its firewall was ready")
        result = _run(["nft", "-j", "list", "table", "inet", "mihomo"], check=False)
        if result.returncode:
            raise NetworkError("Forwarding firewall disappeared during startup")
        entries = json.loads(result.stdout).get("nftables", [])
        chains = {entry["chain"].get("name") for entry in entries if "chain" in entry
                  and entry["chain"].get("family") == "inet" and entry["chain"].get("table") == "mihomo"}
        if marker not in chains:
            raise NetworkError("Forwarding firewall ownership marker changed during startup")
        if expected <= chains:
            return
        time.sleep(.1)
    raise NetworkError("Forwarding core did not finish creating its firewall chains")


def _dns_rules(bridges: Iterable[str], excluded_uids: Iterable[int], marker: str) -> str:
    bridge_names = [_interface(name) for name in sorted(set(bridges))]
    excluded = _uids(excluded_uids)
    if not re.fullmatch(r"fnproxy_owner_[0-9a-f]{24}", marker):
        raise ValueError("Invalid firewall owner marker")
    lines = [f"create table inet {DNS_TABLE}", f"add chain inet {DNS_TABLE} {marker}",
             f"add chain inet {DNS_TABLE} output {{ type nat hook output priority -105; policy accept; }}",
             f"add chain inet {DNS_TABLE} prerouting {{ type nat hook prerouting priority -105; policy accept; }}",
             f"add chain inet {DNS_TABLE} input {{ type filter hook input priority -5; policy accept; }}"]
    for chain in ("output", "prerouting"):
        prefix = f"add rule inet {DNS_TABLE} {chain}"
        lines += [f"{prefix} meta mark & 0xff0000 == 0x80000 return",
                  f"{prefix} meta mark {OUTPUT_MARK} return",
                  f"{prefix} ip daddr 100.64.0.0/10 return",
                  f"{prefix} ip6 daddr fd7a:115c:a1e0::/48 return"]
        if chain == "output" and excluded:
            uid_set = ", ".join(str(uid) for uid in excluded)
            lines.append(f"{prefix} meta skuid {{ {uid_set} }} return")
        if chain == "prerouting":
            if not bridge_names:
                continue
            allowed = ", ".join(json.dumps(name) for name in bridge_names)
            prefix += f" iifname {{ {allowed} }}"
        lines += [f"{prefix} udp dport 53 redirect to :{DNS_PORT}",
                  f"{prefix} tcp dport 53 redirect to :{DNS_PORT}"]
    allowed_input = ", ".join(json.dumps(name) for name in ["lo", *bridge_names])
    for protocol in ("udp", "tcp"):
        lines += [f"add rule inet {DNS_TABLE} input iifname {{ {allowed_input} }} {protocol} dport {DNS_PORT} accept",
                  f"add rule inet {DNS_TABLE} input {protocol} dport {DNS_PORT} drop"]
    return "\n".join(lines) + "\n"


def _take_lock(directory: Path) -> int:
    if fcntl is None:
        raise NetworkError("Linux flock is required")
    lock_path = directory / "lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise NetworkError("Invalid network lease file")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise NetworkBusy("Another desktop client already owns NAS network forwarding") from error
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _remove_recorded_rule(family: str, rule: dict[str, Any], runner: Callable[..., Any]) -> None:
    priority = rule.get("priority")
    if priority not in _RESERVED_PRIORITIES:
        raise NetworkError("State contains an unowned routing priority")
    current = [item for item in _rules(family, runner) if item.get("priority") == priority]
    if not current:
        return
    if current != [rule]:
        raise NetworkError(f"Routing rule {priority} changed; refusing to delete another owner's rule")
    runner(["ip", family, "rule", "del", "pref", str(priority)])


def _claimed_tables(state: dict[str, Any]) -> list[str]:
    # Older journals did not distinguish preflight from resource ownership.
    names = state.get("table_claims", [DNS_TABLE, "mihomo"])
    if not isinstance(names, list) or any(name not in (DNS_TABLE, "mihomo") for name in names):
        raise NetworkError("State contains an unowned firewall table")
    return [name for name in (DNS_TABLE, "mihomo") if name in names]


def _claimed_rules(state: dict[str, Any], family: str, runner: Callable[..., Any]) -> list[dict[str, Any]]:
    """Include mutations journalled *before* the kernel operation, after checking their selectors.

    This closes the SIGKILL window between ``ip rule add`` and its subsequent
    snapshot. A claim is made only after preflight proved the reserved slots
    empty, while the global lease was held. Unexpected selectors and duplicate
    rules remain untouched and prevent a successful recovery report.
    """
    recorded = list(state.get("rules", {}).get(family, []))
    if any(not isinstance(rule, dict) or not _expected_owned_rule(rule) for rule in recorded):
        raise NetworkError("State contains an unexpected recorded routing selector")
    claims = state.get("rule_claims", {}).get(family, [])
    if not isinstance(claims, list) or any(type(priority) is not int or priority not in _RESERVED_PRIORITIES for priority in claims):
        raise NetworkError("State contains an unowned routing claim")
    if not claims:
        return recorded
    current = _rules(family, runner)
    for priority in claims:
        matching = [rule for rule in current if rule.get("priority") == priority]
        if not matching:
            continue
        if len(matching) != 1 or not _expected_owned_rule(matching[0]):
            raise NetworkError(f"Routing claim {priority} no longer has the expected unique selector")
        existing = [rule for rule in recorded if rule.get("priority") == priority]
        if existing and existing != matching:
            raise NetworkError(f"Recorded routing rule {priority} changed")
        if not existing:
            recorded.append(matching[0])
    return recorded


def _route_rows(family: str, runner: Callable[..., Any]) -> list[dict[str, Any]]:
    result = runner(["ip", family, "-j", "route", "show", "table", str(TABLE)], check=False)
    if result.returncode:
        if "FIB table does not exist" in result.stderr:
            return []
        raise NetworkError("Cannot verify the reserved routing table is empty")
    return json.loads(result.stdout)


def _verify_absent(state: dict[str, Any], runner: Callable[..., Any] = _run) -> None:
    """Read kernel state after cleanup; an exited guardian alone proves nothing."""
    errors = []
    if _pid_matches(state.get("core_pid"), state.get("core_start")):
        errors.append("The recorded forwarding core is still running")
    for name in _claimed_tables(state):
        try:
            if _has_table(name, runner):
                detail = "owned" if _table_owned(name, state.get("marker", ""), runner) else "ownership changed"
                errors.append(f"Firewall table {name} remains ({detail})")
        except (NetworkError, OSError, ValueError, subprocess.SubprocessError) as error:
            errors.append(str(error))
    for family in ("-4", "-6"):
        try:
            expected = _claimed_rules(state, family, runner)
            priorities = {rule.get("priority") for rule in expected}
            if priorities and any(rule.get("priority") in priorities for rule in _rules(family, runner)):
                errors.append(f"Recorded {family} routing rules remain")
            if state.get("route_table_claimed", False) and _route_rows(family, runner):
                errors.append(f"Reserved {family} routing table remains occupied")
        except (NetworkError, OSError, ValueError, subprocess.SubprocessError) as error:
            errors.append(str(error))
    if state.get("tun_claimed", state.get("ifindex") is not None):
        try:
            link = runner(["ip", "-j", "link", "show", "dev", DEVICE], check=False)
            if not link.returncode and json.loads(link.stdout):
                errors.append("The claimed TUN interface is still present")
        except (NetworkError, OSError, ValueError, subprocess.SubprocessError) as error:
            errors.append(str(error))
    if errors:
        raise NetworkError("Cleanup could not be verified: " + "; ".join(errors))


def _cleanup_owned(state: dict[str, Any], runner: Callable[..., Any] = _run) -> None:
    """Only recorded exact rules and marker-owned tables may be removed."""
    errors = []
    marker = state.get("marker", "")
    for name in _claimed_tables(state):
        try:
            if _has_table(name, runner):
                if not _table_owned(name, marker, runner):
                    raise NetworkError(f"Firewall table {name} has no matching ownership marker")
                runner(["nft", "delete", "table", "inet", name])
        except (NetworkError, OSError, ValueError, subprocess.SubprocessError) as error:
            errors.append(str(error))
    for family in ("-4", "-6"):
        try:
            recorded = _claimed_rules(state, family, runner)
        except (NetworkError, OSError, ValueError, subprocess.SubprocessError) as error:
            errors.append(str(error))
            # Still attempt exact earlier snapshots; never adopt a changed rule.
            recorded = state.get("rules", {}).get(family, [])
        for rule in reversed(recorded):
            try:
                _remove_recorded_rule(family, rule, runner)
            except (NetworkError, OSError, ValueError, subprocess.SubprocessError) as error:
                errors.append(str(error))
    if state.get("tun_claimed", state.get("ifindex") is not None):
        try:
            link = runner(["ip", "-j", "link", "show", "dev", DEVICE], check=False)
            if not link.returncode:
                rows = json.loads(link.stdout)
                if len(rows) == 1 and state.get("ifindex") == rows[0].get("ifindex"):
                    runner(["ip", "link", "delete", "dev", DEVICE])
                elif rows:
                    errors.append("TUN interface identity changed; no interface was deleted")
        except (NetworkError, OSError, ValueError, subprocess.SubprocessError) as error:
            errors.append(str(error))
    if errors:
        raise NetworkError("; ".join(errors))


def _signal_matching_pid(pid: int, start: str, signum: int) -> bool:
    """Open a pidfd and then recheck start-time, closing the PID reuse race."""
    if not _pid_matches(pid, start):
        return False
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise NetworkError("Race-free pidfd signaling is required on the NAS")
    try:
        descriptor = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        return False
    try:
        if not _pid_matches(pid, start):
            return False
        try:
            signal.pidfd_send_signal(descriptor, signum, None, 0)
        except ProcessLookupError:
            return False
        return True
    finally:
        os.close(descriptor)


def _terminate_core(state: dict[str, Any]) -> None:
    pid = state.get("core_pid")
    start = state.get("core_start")
    if not _pid_matches(pid, start):
        return
    try:
        executable = os.readlink(f"/proc/{pid}/exe")
        if executable.endswith(" (deleted)"):
            executable = executable[:-10]
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\x00")
        if executable != state.get("binary") or os.fsencode(state.get("config", "")) not in cmdline:
            raise NetworkError("Core process identity changed; refusing to signal it")
        _signal_matching_pid(pid, start, signal.SIGTERM)
        deadline = time.monotonic() + 8
        while _pid_matches(pid, start) and time.monotonic() < deadline:
            time.sleep(.1)
        if _pid_matches(pid, start):
            _signal_matching_pid(pid, start, signal.SIGKILL)
            deadline = time.monotonic() + 3
            while _pid_matches(pid, start) and time.monotonic() < deadline:
                time.sleep(.1)
            if _pid_matches(pid, start):
                raise NetworkError("The recorded core did not exit after termination")
    except (ProcessLookupError, FileNotFoundError):
        pass


def _recover_stale(state: dict[str, Any], runner: Callable[..., Any] = _run, *, attempts: int = 2) -> None:
    if not state:
        return
    if _pid_matches(state.get("guard_pid"), state.get("guard_start")):
        raise NetworkBusy("Existing network guardian is still running")
    failure = ""
    for attempt in range(attempts):
        errors = []
        for operation in (_terminate_core, lambda value: _cleanup_owned(value, runner)):
            try:
                operation(state)
            except (NetworkError, OSError, ValueError, subprocess.SubprocessError) as error:
                errors.append(str(error))
        try:
            _verify_absent(state, runner)
            return
        except (NetworkError, OSError, ValueError, subprocess.SubprocessError) as error:
            errors.append(str(error))
        failure = "; ".join(errors)
        if attempt + 1 < attempts:
            time.sleep(.2)
    raise NetworkError("Network recovery failed to verify resource absence: " + failure)


def _finish_guard(state: dict[str, Any], state_path: Path, lock_fd: int,
                  core: subprocess.Popen[Any] | None, core_log: Any) -> None:
    """Cleanup is independent of state/log I/O, including failures in finally."""
    failures = []

    def best_effort(operation: Callable[[], Any], label: str) -> bool:
        try:
            operation()
            return True
        except BaseException as error:
            failures.append(label + ": " + str(error)[:1000])
            return False

    try:
        state["phase"] = "stopping"
        state["cleanup_verified"] = False
        best_effort(lambda: _write_json(state_path, state), "save stopping state")
        best_effort(lambda: _terminate_core(state), "terminate core")
        if core is not None:
            best_effort(lambda: core.wait(timeout=3), "reap core")
        best_effort(lambda: _cleanup_owned(state), "cleanup owned resources")
        state["cleanup_verified"] = best_effort(lambda: _verify_absent(state), "verify resource absence")
        if core_log is not None:
            best_effort(core_log.close, "close core log")
        if failures:
            state["last_error"] = "; ".join([state.get("last_error") or "", *failures]).strip("; ")[:4000]
        state["phase"] = "error" if state.get("last_error") or not state["cleanup_verified"] else "stopped"
        state["stopped_at"] = time.time()
        if not best_effort(lambda: _write_json(state_path, state), "save final state"):
            state["phase"] = "error"
            state["last_error"] = "; ".join([state.get("last_error") or "", failures[-1]]).strip("; ")[:4000]
            try:
                print(state["last_error"], file=sys.stderr)
            except BaseException:
                pass
    finally:
        # A save, close, child-wait or cleanup error may never retain the lease
        # or skip an independent cleanup step above. The supervisor's maintain
        # method reclaims this persisted owner after an uncatchable SIGKILL.
        os.close(lock_fd)


def _supplement_specs() -> list[tuple[int, list[str]]]:
    return [(2, ["fwmark", "0x80000/0xff0000", "lookup", "main"]),
            (4, ["fwmark", hex(OUTPUT_MARK), "lookup", "main"]),
            (5, ["fwmark", hex(INPUT_MARK), "lookup", str(TABLE)])]


def _preflight(spec: dict[str, Any]) -> None:
    if not socks_ready(spec["socks_port"]):
        raise NetworkError("The selected desktop client's SOCKS5 service is not ready")
    if not _management_routes_ok(spec):
        raise NetworkError("A protected LAN or Tailscale management route is not intact")
    for family in ("-4", "-6"):
        if any(item.get("priority") in _RESERVED_PRIORITIES for item in _rules(family)):
            raise NetworkError("Reserved forwarding rule priorities are already occupied")
        routes = _run(["ip", family, "-j", "route", "show", "table", str(TABLE)], check=False)
        if routes.returncode:
            if "FIB table does not exist" not in routes.stderr:
                raise NetworkError("Cannot inspect the reserved routing table")
        elif json.loads(routes.stdout):
            raise NetworkError("The reserved forwarding routing table is already occupied")
    if _has_table("mihomo") or _has_table(DNS_TABLE):
        raise NetworkError("An existing proxy firewall table must not be replaced")
    if _run(["ip", "-j", "link", "show", "dev", DEVICE], check=False).returncode == 0:
        raise NetworkError("The forwarding TUN device is already occupied")
    for family, address in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with socket.socket(family, kind) as probe_socket:
                if family == socket.AF_INET6:
                    probe_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                try:
                    probe_socket.bind((address, DNS_PORT))
                except OSError as error:
                    raise NetworkError("The private forwarding DNS port is already occupied") from error


def _snapshot_rules(state: dict[str, Any]) -> None:
    for family in ("-4", "-6"):
        rows = [item for item in _rules(family) if item.get("priority") in _RESERVED_PRIORITIES]
        if any(not _expected_owned_rule(item) for item in rows):
            raise NetworkError("A reserved routing priority acquired an unexpected rule")
        state["rules"][family] = rows


def _expected_owned_rule(rule: dict[str, Any]) -> bool:
    """Never journal an unrelated rule merely because its priority is reserved."""
    def number(value: Any, default: int = 0) -> int:
        if value is None:
            return default
        if value == "main":
            return 254
        try:
            return int(value, 0) if isinstance(value, str) else int(value)
        except (ValueError, TypeError):
            return -1

    common = {"priority", "src", "dst"}
    if rule.get("src", "all") != "all" or rule.get("dst", "all") != "all" or "not" in rule:
        return False
    priority = rule.get("priority")
    mark = number(rule.get("fwmark"))
    mask = number(rule.get("fwmask"), 0xFFFFFFFF)
    table = number(rule.get("table"))
    selectors = set(rule) - common
    if priority == 2:
        return selectors <= {"fwmark", "fwmask", "table"} and mark == 0x80000 and mask == 0xFF0000 and table == 254
    if priority == 4:
        return selectors <= {"fwmark", "fwmask", "table"} and mark == OUTPUT_MARK and mask == 0xFFFFFFFF and table == 254
    if priority in (5, RULE_INDEX + 1):
        return selectors <= {"fwmark", "fwmask", "table"} and mark == INPUT_MARK and mask == 0xFFFFFFFF and table == TABLE
    if priority == RULE_INDEX:
        return selectors <= {"fwmark", "fwmask", "goto"} and mark == OUTPUT_MARK and mask == 0xFFFFFFFF and rule.get("goto") == RULE_INDEX + 2
    if priority == RULE_INDEX + 2:
        # iproute2 6.1 emits the flag as `"nop": null`; other versions use action.
        return ((selectors == {"nop"} and rule["nop"] is None)
                or (selectors == {"action"} and rule["action"] == "nop"))
    if priority == 32768:
        return selectors == {"table"} and table == TABLE
    return False


def _bridges() -> list[str]:
    links = json.loads(_run(["ip", "-j", "-d", "link", "show"]).stdout)
    return sorted(_interface(item["ifname"]) for item in links
                  if item.get("linkinfo", {}).get("info_kind") == "bridge")


def _pdeathsig() -> None:
    parent = os.getppid()
    if ctypes.CDLL(None).prctl(1, signal.SIGTERM, 0, 0, 0) != 0:
        os._exit(126)
    if os.getppid() != parent:
        os._exit(126)


def _guard(spec_path: str, lock_fd: int) -> int:
    _root_platform()
    spec_file = _trusted_file(Path(spec_path))
    spec = _read_json(spec_file)
    if "management_checks" not in spec:
        # A persisted pre-1.0.5 launch must re-discover its LAN and optional
        # Tailscale before the guardian can claim any network resources.
        spec.update(_discover_network(interface=spec.get("interface"), management_target=spec.get("management_target"),
                                      management_device=spec.get("management_device")))
    _management_checks(spec)
    directory = _private_directory(Path(spec["state_dir"]))
    work = _private_directory(Path(spec["work_dir"]))
    lock_metadata = os.fstat(lock_fd)
    if lock_metadata.st_ino != (directory / "lock").stat().st_ino or lock_metadata.st_uid != 0:
        raise NetworkError("Invalid inherited network lease")
    state_path = directory / "owner.json"
    state = {**spec, "phase": "starting", "guard_pid": os.getpid(), "guard_start": _pid_start(os.getpid()),
             "core_pid": None, "core_start": None, "rules": {"-4": [], "-6": []}, "ifindex": None,
             "rule_claims": {"-4": [], "-6": []}, "table_claims": [],
             "tun_claimed": False, "route_table_claimed": False, "cleanup_verified": False,
             "started_at": time.time(), "last_error": None}
    _write_json(state_path, state)
    stop_requested = False

    def request_stop(_signum: int, _frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    core = None
    core_log = None
    try:
        _preflight(spec)
        configuration = build_config(spec["socks_port"], excluded_uids=spec["excluded_uids"], interface=spec["interface"],
                                     lan_gateway=spec["lan_gateway"], tailscale=spec["tailscale"])
        config_path = work / "network.json"
        _write_json(config_path, configuration)
        state["config"] = str(config_path)
        _write_json(state_path, state)
        _run([spec["binary"], "-t", "-d", str(work), "-f", str(config_path)], timeout=30)
        for family in ("-4", "-6"):
            for priority, selector in _supplement_specs():
                state["rule_claims"][family].append(priority)
                _write_json(state_path, state)
                _run(["ip", family, "rule", "add", "pref", str(priority), *selector])
                _snapshot_rules(state)
                _write_json(state_path, state)
        log_path = work / "network.log"
        if log_path.is_symlink():
            raise NetworkError("Network log must not be a symlink")
        log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
        core_log = os.fdopen(log_fd, "ab", buffering=0)
        environment = {key: value for key, value in os.environ.items()
                       if key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy", "disable_nftables"}}
        for family in ("-4", "-6"):
            state["rule_claims"][family] += [RULE_INDEX, RULE_INDEX + 1, RULE_INDEX + 2, 32768]
        state["table_claims"].append("mihomo")
        state["tun_claimed"] = True
        state["route_table_claimed"] = True
        _write_json(state_path, state)
        core = subprocess.Popen([spec["binary"], "-d", str(work), "-f", str(config_path)],
                                stdout=core_log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                env=environment, close_fds=True, preexec_fn=_pdeathsig)
        state.update(core_pid=core.pid, core_start=_pid_start(core.pid))
        _write_json(state_path, state)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if stop_requested or core.poll() is not None:
                raise NetworkError("Forwarding core stopped during startup")
            link = _run(["ip", "-j", "link", "show", "dev", DEVICE], check=False)
            if not link.returncode and _has_table("mihomo"):
                rows = json.loads(link.stdout)
                if len(rows) == 1:
                    state["ifindex"] = rows[0]["ifindex"]
                    break
            time.sleep(.2)
        else:
            raise NetworkError("Forwarding core did not create its TUN and nftables resources")
        # Publish ownership before inspecting upstream-created policy rules.
        # A failure in their validation must still permit bounded cleanup.
        _write_json(state_path, state)
        _run(["nft", "create", "chain", "inet", "mihomo", state["marker"]])
        if not _table_owned("mihomo", state["marker"]):
            raise NetworkError("Forwarding firewall ownership marker could not be verified")
        _await_core_firewall(state["marker"], core, lambda: stop_requested)
        _snapshot_rules(state)
        _write_json(state_path, state)
        for chain in ("output", "output_udp_icmp"):
            _run(["nft", "insert", "rule", "inet", "mihomo", chain,
                  "meta", "mark", "&", "0xff0000", "==", "0x80000", "return"])
        bridges = _bridges()
        state["table_claims"].append(DNS_TABLE)
        _write_json(state_path, state)
        _run(["nft", "-f", "-"], input=_dns_rules(bridges, spec["excluded_uids"], state["marker"]))
        if not _management_routes_ok(spec) or not socks_ready(spec["socks_port"]):
            raise NetworkError("Management or desktop SOCKS health check failed after activation")
        state["phase"] = "active"
        _write_json(state_path, state)
        while not stop_requested:
            if core.poll() is not None:
                raise NetworkError("Forwarding core exited; restoring direct networking")
            if not _pid_matches(spec["parent_pid"], spec["parent_start"]):
                raise NetworkError("Application supervisor exited; restoring direct networking")
            if not socks_ready(spec["socks_port"]):
                raise NetworkError("Desktop SOCKS service disconnected; restoring direct networking")
            if not _management_routes_ok(spec):
                raise NetworkError("A protected management route changed; restoring direct networking")
            current_bridges = _bridges()
            if current_bridges != bridges:
                if not _table_owned(DNS_TABLE, state["marker"]):
                    raise NetworkError("The forwarding DNS table ownership changed")
                replacement = f"delete table inet {DNS_TABLE}\n" + _dns_rules(current_bridges, spec["excluded_uids"], state["marker"])
                _run(["nft", "-f", "-"], input=replacement)
                bridges = current_bridges
            # Existing log descriptor is append-only, so truncation preserves logging.
            if log_path.stat().st_size > 16 * 1024 * 1024:
                with log_path.open("wb"):
                    pass
            for _ in range(10):
                if stop_requested:
                    break
                time.sleep(.2)
    except BaseException as error:
        state["last_error"] = str(error)[:2000]
    finally:
        _finish_guard(state, state_path, lock_fd, core, core_log)
    return 1 if state["phase"] == "error" else 0


class NetworkController:
    """Synchronous root-supervisor API. Both application packages share STATE_DIR.

    Pass both dedicated GUI user IDs in ``excluded_uids``.  ``start`` waits for
    activation; ``stop`` only stops this app's guardian and verifies cleanup;
    ``status`` is read-only. The supervisor must call ``maintain`` every two
    seconds, including while forwarding is not desired, to recover SIGKILLs.
    UDP/QUIC, IPv6 and Docker acceptance still require actual NAS E2E checks.
    """

    def __init__(self, app: str, work_dir: str | os.PathLike[str], binary: str | os.PathLike[str],
                 socks_port: int, *, excluded_uids: Iterable[int], interface: str | None = None,
                 management_target: str | None = None, management_device: str | None = None,
                 state_dir: str | os.PathLike[str] = STATE_DIR) -> None:
        if app not in _APPS:
            raise ValueError("Unknown desktop client")
        excluded = _uids(excluded_uids)
        build_config(socks_port, excluded_uids=excluded, interface=interface)
        target = _management_address(management_target) if management_target is not None else None
        if management_device is not None and target is None:
            raise ValueError("A management device override requires a target")
        self.app = app
        self.work_dir = Path(work_dir)
        self.binary = Path(binary)
        self.socks_port = socks_port
        self.excluded_uids = excluded
        self.interface = _interface(interface) if interface is not None else None
        self.management_target = target
        self.management_device = _interface(management_device) if management_device is not None else None
        self.state_dir = Path(state_dir)
        self._child: subprocess.Popen[Any] | None = None

    def status(self) -> dict[str, Any]:
        state = _read_json(self.state_dir / "owner.json")
        live = _pid_matches(state.get("guard_pid"), state.get("guard_start"))
        cleanup_verified = not state or bool(state.get("cleanup_verified") and not live)
        return {"active": bool(live and state.get("phase") == "active"),
                "owner": state.get("app"), "owned": state.get("app") == self.app,
                "phase": state.get("phase", "stopped"), "socks_port": state.get("socks_port"),
                "started_at": state.get("started_at"), "last_error": state.get("last_error"),
                "cleanup_verified": cleanup_verified,
                "needs_recovery": bool(state and not live and not cleanup_verified),
                "core_pid": state.get("core_pid") if live else None,
                "acceptance": "NAS TCP/DNS/UDP/IPv6/Docker checks required"}

    def recover(self) -> dict[str, Any]:
        """Bounded recovery of this app's dead guardian, under a reclaimed lease.

        An owner/token change, live guardian, changed kernel selector or absent
        ownership marker can never be overwritten by recovery. An error leaves
        the owner journal in place for another attempt or operator inspection.
        """
        _root_platform()
        prior = _read_json(self.state_dir / "owner.json")
        if not prior:
            return self.status()
        if prior.get("app") != self.app:
            raise NetworkBusy("This client must not recover another client's forwarding session")
        if _pid_matches(prior.get("guard_pid"), prior.get("guard_start")):
            raise NetworkBusy("The network guardian is still running")
        directory = _private_directory(self.state_dir)
        descriptor = _take_lock(directory)
        try:
            current = _read_json(directory / "owner.json")
            identity = lambda value: (value.get("app"), value.get("token"), value.get("guard_pid"), value.get("guard_start"))
            if not current or identity(current) != identity(prior):
                raise NetworkBusy("Network ownership changed while acquiring the recovery lease")
            try:
                _recover_stale(current)
            except BaseException as error:
                current.update(phase="error", cleanup_verified=False,
                               last_error=("Network cleanup recovery failed: " + str(error))[:4000])
                try:
                    _write_json(directory / "owner.json", current)
                except BaseException as save_error:
                    raise NetworkError(str(current["last_error"]) + "; saving recovery state failed: " + str(save_error)) from error
                raise NetworkError(current["last_error"]) from error
            previous_error = current.get("last_error")
            current.update(phase="stopped", cleanup_verified=True, stopped_at=time.time(),
                           recovered_at=time.time(), last_error=None)
            if previous_error:
                current["previous_error"] = previous_error
            try:
                _write_json(directory / "owner.json", current)
            except BaseException as error:
                raise NetworkError("Resource absence was verified, but the recovery journal could not be saved: " + str(error)) from error
            if self._child is not None:
                self._child.poll()
            return {**self.status(), "recovered": True}
        finally:
            os.close(descriptor)

    def maintain(self) -> dict[str, Any]:
        """Supervisor watchdog hook; a live/foreign owner is never interrupted."""
        _root_platform()
        state = _read_json(self.state_dir / "owner.json")
        if (not state or state.get("app") != self.app
                or _pid_matches(state.get("guard_pid"), state.get("guard_start"))
                or (state.get("cleanup_verified") and state.get("phase") in ("stopped", "error"))):
            return self.status()
        try:
            return self.recover()
        except NetworkBusy:
            # Another controller may have acquired the lease while this one
            # was checking. Re-read its state and let the next tick decide.
            return self.status()

    def start(self, timeout: float = 55) -> dict[str, Any]:
        _root_platform()
        directory = _private_directory(self.state_dir)
        work = _private_directory(self.work_dir)
        binary = _trusted_file(self.binary)
        _trusted_file(Path(__file__))
        prior = _read_json(directory / "owner.json")
        if prior.get("app") == self.app and self.status()["active"]:
            return self.status()
        descriptor = _take_lock(directory)
        guardian_log = None
        try:
            # Discovery and route checks precede even stale-resource cleanup:
            # ambiguous/unavailable management must not cause network writes.
            plan = _discover_network(interface=self.interface, management_target=self.management_target,
                                     management_device=self.management_device)
            _recover_stale(_read_json(directory / "owner.json"))
            token = secrets.token_hex(12)
            spec = {"app": self.app, "token": token, "marker": "fnproxy_owner_" + token,
                    "state_dir": str(directory), "work_dir": str(work), "binary": str(binary),
                    "socks_port": self.socks_port, "excluded_uids": self.excluded_uids,
                    **plan,
                    "parent_pid": os.getpid(), "parent_start": _pid_start(os.getpid())}
            spec_path = work / "network-launch.json"
            _write_json(spec_path, spec)
            log_fd = os.open(work / "guardian.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
            guardian_log = os.fdopen(log_fd, "ab", buffering=0)
            self._child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--guard", str(spec_path), str(descriptor)],
                                           stdin=subprocess.DEVNULL, stdout=guardian_log, stderr=subprocess.STDOUT,
                                           pass_fds=(descriptor,), start_new_session=True, close_fds=True)
        finally:
            # Do not LOCK_UN: the guardian holds the inherited open-file lease.
            os.close(descriptor)
            if guardian_log is not None:
                guardian_log.close()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = _read_json(directory / "owner.json")
            if state.get("token") == token:
                if state.get("phase") == "active":
                    return self.status()
                if state.get("phase") == "error":
                    raise NetworkError(state.get("last_error") or "Forwarding activation failed")
            if self._child.poll() is not None:
                raise NetworkError(state.get("last_error") or "Network guardian failed before activation")
            time.sleep(.15)
        self.stop()
        raise NetworkError("Timed out activating native network forwarding")

    def stop(self, timeout: float = 18) -> dict[str, Any]:
        _root_platform()
        state = _read_json(self.state_dir / "owner.json")
        if not state:
            return self.status()
        if state.get("app") != self.app:
            raise NetworkBusy("This client must not stop another client's forwarding session")
        pid, start = state.get("guard_pid"), state.get("guard_start")
        if _pid_matches(pid, start):
            _signal_matching_pid(pid, start, signal.SIGTERM)
            deadline = time.monotonic() + timeout
            while _pid_matches(pid, start) and time.monotonic() < deadline:
                if self._child is not None:
                    self._child.poll()
                time.sleep(.1)
            if _pid_matches(pid, start):
                raise NetworkError("Network guardian has not finished cleanup; its lease was retained")
        # This also inspects a guardian's final cleanup error and retries only
        # marker/identity-owned resources. Never infer direct networking merely
        # from its process having exited or its phase saying "stopped".
        return self.recover()


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--guard":
        try:
            raise SystemExit(_guard(sys.argv[2], int(sys.argv[3])))
        except Exception as failure:
            print(type(failure).__name__ + ": " + str(failure), file=sys.stderr)
            raise SystemExit(1)
    raise SystemExit("Network control is available through the native supervisor API")
