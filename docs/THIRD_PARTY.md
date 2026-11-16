# 第三方软件与对应源码

[返回首页](../README.md) · [构建说明](BUILD.md)

本仓库维护 fnOS 原生封装，保留上游 Linux 图形程序。它是社区封装，与原版客户端、Mihomo 或飞牛官方没有隶属关系，也不替代上游项目的身份。

## 本仓库与上游许可

封装源码采用根目录 [GPLv3 许可证](../LICENSE)。上游组件的原许可证与版权声明保留原文；中文内容用于解释和导航，不替代原条款。

| 组件 | 本次固定版本 | 来源与许可证 |
| --- | --- | --- |
| v2rayN | 7.25.6 | [精确版本源码](https://github.com/2dust/v2rayN/tree/7.25.6) · [对应源码归档](https://github.com/2dust/v2rayN/archive/refs/tags/7.25.6.tar.gz) · [上游原始许可](../packaging/licenses/v2rayN-LICENSE.txt) |
| 独立 Mihomo 网络组件 | 1.19.34 | [精确版本源码](https://github.com/MetaCubeX/mihomo/tree/v1.19.34) · [源码归档](https://github.com/MetaCubeX/mihomo/archive/refs/tags/v1.19.34.tar.gz) · [原始许可](../packaging/licenses/mihomo-LICENSE.txt) |
| SQLite 兼容库 | Debian 12 的 3.40.1 系列，供 v2rayN 适配使用 | [来源记录](../vendor/sqlite/SOURCE.json) · [说明](../vendor/sqlite/NOTICE.md) · [Debian 版权记录](../vendor/sqlite/COPYRIGHT.debian) |

客户端原始整包中随附的代理内核、GUI 框架和资源，各自保留其上游许可证。相关项目包括 [Xray](https://github.com/XTLS/Xray-core)、[sing-box](https://github.com/SagerNet/sing-box)、[Mihomo](https://github.com/MetaCubeX/mihomo)、[Avalonia](https://github.com/AvaloniaUI/Avalonia) 和 [Tauri](https://github.com/tauri-apps/tauri)。精确载荷与版本来源以本次发布的构建清单和对应源码资料为准。

## 获取对应源码

本仓库在发布标签处提供封装源码，Release 同时列出固定上游版本、对应源码入口或归档以及校验资料。下载二进制时，请同时保留相关许可和来源说明。上游整包更新后，实际采用的版本可能变化，维护者需相应更新来源与对应源码记录。

NAS 的图形环境和网页桌面依赖来自安装者已配置的 Debian 软件源，例如 Xvfb、Openbox、x11vnc、noVNC、DBus、GTK/WebKitGTK 及 Python 组件；它们的 Debian 版权记录保留在 NAS 各软件包的标准版权目录。

## 项目素材

本仓库的头图为项目自制 SVG 示意图。界面图片来自历史原生界面记录，私人配置与日志已作不透明遮盖，保留上游界面中的名称和标识以说明实际使用的软件；这些名称与标识的权利归各自权利人。

## 本版源码附件

[对应源码压缩包](https://github.com/CyberShadowX/v2rayN-For-FNOS/releases/download/v1.0.5/v2rayN-For-FNOS-1.0.5-corresponding-source.tar.gz) 包含 `wrapper/` 封装源码和 `upstream/` 固定源码归档；[来源清单](../SOURCES.json) 记录各归档来源、字节数与 SHA-256。压缩包内含上游的构建脚本、依赖清单和许可，封装构建方法见 [BUILD.md](BUILD.md)。这是来源可核对的发布材料，不承诺第三方现成发行包可逐字节复现。

随包 Xray 的内置版本为 26.10.10，构建标识为 `701af60`，对应[官方完整提交](https://github.com/XTLS/Xray-core/commit/701af60772cda123492f86e383e1fdba066614a9)；使用该提交源码归档，避免依赖当前不可访问的版本标签。随包 sing-box 与 Mihomo 的提交由 Go 构建信息记录。

v2rayN 的 `v2rayN/GlobalHotKeys` 子模块源码按发行标签的 gitlink 固定到 `162d401dfe0140b41d1fa349b9aadb4060e739b1`，作为独立归档放在源码附件的 `upstream/`。若自行编译原版客户端，将其内容恢复到该子模块目录，再按上游随附构建流程准备依赖。
