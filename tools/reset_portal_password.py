"""Reset only one app's web password; root required, no password CLI arguments."""
import argparse
import getpass
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from runtime.credentials import CredentialError, require_administrator, reset_password


class PrivateParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally repeats unknown argument values. A caller who used
        # an unsupported --password option must not have that value echoed.
        self.exit(2, "参数无效，请使用 --help 查看用法；密码仅可交互输入或由标准输入提供。\n")


def main():
    parser = PrivateParser(description="重置本应用的网页登录密码，不清理节点、订阅或 TLS。需要 NAS 管理员 root 权限。")
    parser.add_argument("--app", required=True, choices=("v2rayn", "clash"))
    parser.add_argument("--var", required=True, type=Path, help="fnOS 为本应用分配的 var 数据目录")
    parser.add_argument("--password-stdin", action="store_true", help="从标准输入读取新密码及确认各一行，不接受命令行密码")
    args = parser.parse_args()
    try:
        require_administrator()
        if args.password_stdin:
            first = sys.stdin.readline(2050)
            second = sys.stdin.readline(2050)
            if not first.endswith("\n") or not second.endswith("\n") or sys.stdin.read(1):
                raise CredentialError("标准输入须仅包含新密码与确认两行")
            new_password = first.removesuffix("\n").removesuffix("\r")
            confirmation = second.removesuffix("\n").removesuffix("\r")
        else:
            new_password = getpass.getpass("新访问密码（12–128 字符）：")
            confirmation = getpass.getpass("再次输入新密码：")
        if new_password != confirmation:
            raise CredentialError("两次输入的新密码不一致")
        reset_password(args.var, args.app, new_password)
    except CredentialError as error:
        print("密码重置未完成：" + str(error), file=sys.stderr)
        return 1
    except (PermissionError, OSError, EOFError):
        print("密码重置未完成：请核对 root 权限、应用数据目录、密码要求与两次输入。", file=sys.stderr)
        return 1
    print("访问密码已更新；旧网页登录会话将失效，请使用新密码重新登录。节点与 TLS 保持不变。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
