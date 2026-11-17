# 从源码构建

[返回首页](../README.md) · [第三方来源](THIRD_PARTY.md)

两个公开仓库使用相同的封装框架和测试集，分别通过 `publication.json` 选择默认应用。本仓库默认目标为 **`v2rayn`**，输出 `fnv2rayn-1.0.6-x86.fpk`。

## 构建环境

| 组件 | 要求 |
| --- | --- |
| 构建操作系统 | Windows，使用已验证的 fnpack Windows 流程 |
| Python | 3.11 或更高版本 |
| Python 依赖 | `requirements-build.txt`：Pillow、aiohttp 与 PyYAML |
| fnpack | 1.2.3，准备脚本校验指定来源与摘要 |
| 最低 fnOS 声明 | manifest：1.2.1010 |
| 本轮实测环境 | fnOS 1.2.1011 / Debian 12 / x86_64 |

本项目构建的是 Linux NAS 应用；在 Windows 上打包不代表客户端可作为 Windows 程序安装。其他构建操作系统的完整打包流程未验证。

## 获取源码与依赖

```powershell
git clone https://github.com/CyberShadowX/v2rayN-For-FNOS.git
Set-Location v2rayN-For-FNOS
python -m pip install -r requirements-build.txt
python tools/prepare_public_build.py --apps v2rayn
```

准备脚本获取固定版本的官方客户端发行包、独立 Mihomo 网络组件和所需构建工具，并核对来源、大小与 SHA-256。遇到校验失败时先查明原因，不跳过校验或将陌生镜像直接视为同一文件。

构建输入保存在仓库 `work/`，包括上游解包目录和 `work/tools/fnpack.exe`。`vendor/` 保留固定依赖的来源与许可证。Git 本身不携带已下载的上游整包。

## 检查与打包

```powershell
python -m unittest discover -s tests -q
python tools/build_packages.py
```

构建输出位于 `dist/`，包含本应用 FPK、`SHA256SUMS.txt` 和 `build-inventory.json`。构建清单用于核对最终安装包中的文件，不代替安装后的 GUI 和网络验收。

Linux 特定测试可能因构建机平台或权限条件跳过；查看实际测试输出，不能把跳过记为通过。浏览器交互、访问密码、升级保留、网络开关及目标 NAS 的验收独立记录。实际测试命令与结果见该版本 [验证说明](VALIDATION.md) 和 Release。

## 目录用途

| 目录 | 内容 |
| --- | --- |
| `adapters/` | 官方客户端与网络组件的发行包选择、校验和适配 |
| `runtime/` | 图形桌面、网页入口、网络接管、生命周期、更新回滚 |
| `web/` | 中文网页管理界面 |
| `packaging/` | FPK 生命周期、图标、许可证与封装材料 |
| `tools/` | 上游准备和打包工具 |
| `tests/` | 原生运行与安全边界相关测试 |
| `vendor/` | 固定兼容库及第三方来源/版权记录 |
| `work/` | 已下载的构建输入与本机工作材料 |
| `build/` | 打包暂存树 |
| `dist/` | 最终交付文件 |

重新构建前，先检查是否需要保留 `dist/` 中的旧交付件。`work/` 含构建直接依赖的输入，清理时先区分可重新获取的材料和需要保留的验证、恢复资料。不要将节点、口令、订阅、TLS 私钥或个人运行配置加入源码或安装包。

## 随包说明与访问恢复工具

新包的网页帮助、应用原生图标及 `tools/reset_portal_password.py` 应随 FPK 一并核对。首次登录、网页改密和管理员重置的操作合同见 [ACCESS.md](ACCESS.md)，模式与导入格式见 [USER_GUIDE.md](USER_GUIDE.md)。维护者更新这些功能时，同步软件内帮助、公开文档、截图、版本记录与 Release。

## 本轮检查环境与浏览器测试

本轮 Windows 源码测试 249 项（227 通过、22 项平台检查跳过）；目标 NAS 在 Python 3.11.2 / aiohttp 3.8.4 下以 root 执行 249/249、无跳过。Chromium／Chrome 离线交互检查 13/13；NAS 上实际图形桌面、网络开关和访问管理另有实测记录。完整边界见[验证说明](VALIDATION.md)。

浏览器用例需要可用的 Node.js、Playwright 与对应 Chromium。准备好该依赖后运行：

```powershell
node --test tests/frontend.browser.test.cjs
```

默认加载本地 `playwright` 模块；复用已核验的其他模块位置时，可在当前测试进程设置 `FNOS_PLAYWRIGHT_MODULE`。浏览器测试使用本地替身服务，不携带真实 NAS、节点或密码；不以其结果替代实机网络与会话检查。
