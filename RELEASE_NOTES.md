# v2rayN For FNOS v1.0.6

![项目头图](https://raw.githubusercontent.com/CyberShadowX/v2rayN-For-FNOS/v1.0.6/docs/assets/hero.svg)

原版 v2rayN 图形客户端、NAS/Docker 网络接管和上游更新，在飞牛中通过浏览器使用。

## 本次更新

- NAS 网络改为手机式单开关，分开显示启用、关闭、操作中、待确认、待恢复和其他客户端占用状态。
- 修正旧版成功后按钮变淡、鼠标仍显示等待的交互，状态回显跟随后台结果。
- 导入入口按客户端显示实际格式：v2rayN 使用节点分享链接，Clash 使用 Mihomo YAML；完善格式提示。
- 登录页、页眉和浏览器标签页使用各自原生应用图标。
- 增加网页修改访问密码和 root 管理员重置，保留既有访问密码、节点及配置。
- 补齐模式／系统代理／路由、密码保存、更新与恢复中文指南，软件内帮助与仓库同步。

## 下载与平台

| 项目 | 说明 |
| --- | --- |
| FPK | `fnv2rayn-1.0.6-x86.fpk` |
| 本轮实测平台 | fnOS 1.2.1011 / Debian 12 / x86_64 |
| 最低 fnOS 声明 | manifest：1.2.1010 |
| 随包 v2rayN | 7.25.6 |
| 独立网络组件 | Mihomo 1.19.34 |
| 网页入口 | HTTPS 18111 |

从[本次 Release](https://github.com/CyberShadowX/v2rayN-For-FNOS/releases/tag/v1.0.6)下载本应用 FPK，按同页 `SHA256SUMS.txt` 核对。两个客户端可以同时打开图形界面，NAS 网络接管互斥；客户端内置 TUN 关闭，推荐模式见[使用指南](https://github.com/CyberShadowX/v2rayN-For-FNOS/blob/main/docs/USER_GUIDE.md)。

## 升级与访问密码

这是飞牛封装更新，在飞牛应用中心安装新 FPK。右侧“一键更新”只管理上游程序、内核和资源，不会升级右侧网页封装。

升级前保存旧包和必要配置，确认管理连接与恢复入口。升级、重启及回滚可能短暂中断图形桌面和代理访问。保留应用数据时，既有密码、节点与配置继续使用；主动改密后本应用旧网页登录／VNC 会话失效。首次读取、保存与管理员重置见[密码指南](https://github.com/CyberShadowX/v2rayN-For-FNOS/blob/main/docs/ACCESS.md)。

## 本轮已完成验证

- Windows 源码 249 项：227 通过、22 项平台检查跳过；NAS root 249/249，无跳过。
- Chrome 离线交互 13/13，发布保护 24/24；相关组件独立审查 PASS，Important 已关闭。
- 真实完成飞牛应用中心原位升级，核对既有访问凭据、TLS、节点库和配置保留；节点记录的 40 个稳定字段与升级前备份一致，两个 GUI、HTTPS、原生图标和离线帮助通过。
- 真实页面开关的蓝右／灰左、稳定状态指针与互斥通过；改密、管理员重置、API/WebSocket 会话撤销及文件权限隔离用例在 NAS 上实际运行。
- 隔离数据下的真实 HTTPS 门户、实际应用用户与 root 主控完成端到端改密和 CLI 重置；两条真实 WebSocket 断开、旧密码失效，新密码可登录，TLS／节点测试数据保留。
- 两应用各完成官方整包真实下载与摘要校验、同版本重装、程序及 profile 回滚，恢复后 GUI、网络与原有数据检查通过。
- 两客户端分别接管时，NAS、CloudSaver、Chromium 的 Google HTTP 204／YouTube HTTP 200 检查通过。
- v2rayN 独立转发进程退出后，guardian 完成清理、摘要自动恢复“直连已恢复”，随后重新接管成功；本项未停止 root 主控和远程管理连接。
- 官方 v2rayN 在隔离 profile 中识别合成 VMess，未改正式节点库；VMess 远端连接未测试。

发布流程要求目标提交通过 Windows／Ubuntu 单元测试与浏览器 CI，当前状态见[源码检查工作流](https://github.com/CyberShadowX/v2rayN-For-FNOS/actions/workflows/checks.yml)。整机重启、强杀主控、QUIC／视频与原生远端 IPv6 等专项边界见[验证说明](https://github.com/CyberShadowX/v2rayN-For-FNOS/blob/main/docs/VALIDATION.md)。

## 同页附件

| 文件 | 用途 |
| --- | --- |
| `fnv2rayn-1.0.6-x86.fpk` | Linux x86_64 飞牛安装包 |
| `SHA256SUMS.txt` | 安装包、源码及说明附件 SHA-256 |
| `build-inventory.json` | 最终 FPK 文件摘要与结构检查 |
| `SOURCES.json` | 固定上游来源和源码归档摘要 |
| `v2rayN-For-FNOS-1.0.6-corresponding-source.tar.gz` | 封装源码、构建资料和固定上游源码归档 |
| `RELEASE_NOTES_zh-CN.md` | 首次发布说明离线副本 |

发布工具核对六项附件集合及服务端摘要；下载后请按 `SHA256SUMS.txt` 核对其中列出的文件。

本项目为社区封装，第三方组件保留原始许可。GPLv3、对应源码及构建入口见[来源说明](https://github.com/CyberShadowX/v2rayN-For-FNOS/blob/main/docs/THIRD_PARTY.md)，平台验证和已知问题见[验证说明](https://github.com/CyberShadowX/v2rayN-For-FNOS/blob/main/docs/VALIDATION.md)。
