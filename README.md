# 1IPW.CN

1IPW.CN 是一个面向 IP、DNS、网络连通性和网站安全检测的开源工具站。本仓库包含 React/TDesign 前端，以及基于 [nomdn/ipw-cn](https://github.com/nomdn/ipw-cn) 扩展的 Go 后端。

项目目前尚未确定正式版本号，`package.json` 暂使用 `0.0.0`，不代表稳定版本发布。

## 主要能力

- 当前 IP 与指定 IP 归属地查询
- DNS、DNSSEC、WHOIS、SSL 和网站详情查询
- 多节点 DNS、TCPing、Traceroute 与网站测速
- HTTP、TCP、UDP 协议测试
- 邮箱安全、RBL、CDN 和安全响应头检测
- 兼容 Lemon IPW RC7.1 测速节点的请求路径
- 节点地址与访问 Key 仅由服务端环境变量注入

## 目录

- `src/`：React/TDesign 前端
- `vite.config.ts`：本地开发代理；私有节点配置只从环境变量读取
- `backend-src-20260802/nomdn-ipw-cn-a869787/`：Go 后端源码
- `.env.example`：不含任何节点地址或 Key 的配置模板

部署目录、备份、构建产物、节点清单、访问凭据和本地日志不属于开源提交。

## 本地开发

需要 Node.js、pnpm 和 Go。

```powershell
pnpm install
Copy-Item .env.example .env.local
pnpm dev
```

前端开发服务器默认只监听 `127.0.0.1:5174`，并将 `/api` 转发到本机 `127.0.0.1:8080`。

启动后端：

```powershell
Set-Location backend-src-20260802/nomdn-ipw-cn-a869787
go run .
```

## 节点接入配置

节点地址和 Key 不应写入源码、前端变量或 Git 历史。

后端公共查询代理使用以下成对变量：

```text
IPW_PUBLIC_NODE_<NODE>_URL
IPW_PUBLIC_NODE_<NODE>_KEY
```

当前支持的 `<NODE>` 名称为 `ZAOZHUANG`、`HONGKONG`、`XIAN2`、`SHIYAN`、`HONGKONG2` 和 `JDCLOUD`。只有 URL 与 Key 都存在时，对应节点才会注册到 `/v1/public-query/nodes`。

本地 Vite 开发代理使用 `IPW_DEV_<NODE>_TARGET` 与 `IPW_DEV_<NODE>_KEY`。这些变量不使用 `VITE_` 前缀，因此不会注入浏览器构建产物。生产环境应由 Nginx、Caddy 或其他反向代理提供相同的同源路径。

节点 Key 通过服务端 `Authorization: Bearer ...` 请求头发送。不要将 Key 放在 URL、浏览器代码、公开文档或提交记录中。

## 验证

```powershell
pnpm build

Set-Location backend-src-20260802/nomdn-ipw-cn-a869787
go test ./...
```

## 开源协议

本项目采用 [GNU General Public License v3.0](LICENSE)，SPDX 标识为 `GPL-3.0-only`。基于上游代码的部分保留原作者版权与许可信息。
