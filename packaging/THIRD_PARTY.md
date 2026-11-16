# 第三方软件、许可证与对应源码

本项目是社区维护的飞牛 fnOS 原生封装，与飞牛、v2rayN、Clash Verge Rev 及各内核上游没有隶属关系。封装代码采用 GNU GPL 第 3 版；第三方程序保留各自的版权与许可证，不因放在同一 FPK 中而变更许可。

## 官方桌面程序与独立网络组件

| 组件 | 随包版本 | 原始许可证 | 官方源码与构建材料 |
| --- | --- | --- | --- |
| v2rayN | 7.25.6 | GPLv3，原文见 `licenses/v2rayN-LICENSE.txt` | https://github.com/2dust/v2rayN/tree/7.25.6 |
| Clash Verge Rev | 2.5.10 | GPLv3，原文见 `licenses/clash-verge-rev-LICENSE.txt` | https://github.com/clash-verge-rev/clash-verge-rev/tree/v2.5.10 |
| 独立 Mihomo 网络组件 | 1.19.34 | GPLv3，原文见 `licenses/mihomo-LICENSE.txt` | https://github.com/MetaCubeX/mihomo/tree/v1.19.34 |

桌面程序取自官方 Linux 发行包，客户端、随附内核及资源文件保持上游字节内容；FPK 将这些文件放到飞牛应用目录，不运行上游 Debian 包的维护脚本。实际载荷由构建清单记录。独立 Mihomo 的来源、大小和 SHA-256 固定在 `vendor/mihomo/SOURCE.json`，FPK 中对应为 `network-core/source.json`。

每次公开发布提供封装源码、上游固定版本或提交的源码归档和 SOURCES.json 来源清单，作为同一 Release 的对应源码附件。各内核的源码身份应按实际二进制、官方发行材料和构建信息核对，不能把最新源码当作任意旧二进制的精确来源。原始许可证保留原文，中文说明用于导航。

## 随客户端发行的其他组件

官方桌面发行包还包含 Xray、sing-box、Mihomo、Avalonia/Tauri 及其他运行库、地理数据等，它们继续遵循各自原始许可和上游声明。对应构建与来源入口：

- Xray：https://github.com/XTLS/Xray-core
- sing-box：https://github.com/SagerNet/sing-box
- Mihomo：https://github.com/MetaCubeX/mihomo
- Avalonia：https://github.com/AvaloniaUI/Avalonia
- Tauri：https://github.com/tauri-apps/tauri

随包内核与独立网络组件可能版本不同。更新动作会校验官方稳定客户端完整发行包及独立网络组件，并将程序切换与配置快照、恢复流程配合；它不改变 FPK 封装版本号。

## SQLite 兼容库

v2rayN 使用应用目录中的 SQLite 兼容别名，以兼容 Debian 12。其上游 SQLite 为公共领域，Debian 包的版权与补丁声明保留在 vendor/sqlite/，FPK 中为 compat/。来源、精确包版本和哈希见 SOURCE.json，许可原文见 COPYRIGHT.debian。此库仅用于应用私有目录，不替换系统 SQLite 或 glibc。

## 系统图形与网页桌面依赖

Xvfb/X.Org、Openbox、x11vnc、noVNC、DBus、GTK3、WebKitGTK、Python/aiohttp 和 Noto 字体通过设备已配置的 Debian 软件源安装，不作为第三方二进制内嵌到 FPK。安装后的版权和许可位于设备 /usr/share/doc/<package>/copyright。

安装包不包含账号、节点、订阅、网页口令、TLS 私钥或特定 NAS 的运行配置。初次安装时，在安装设备上生成并限制访问所需的凭据与密钥。
