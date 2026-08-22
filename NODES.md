# 1IPW.CN 节点对接文档

> 适用版本：`v0.1.0-rc9.3.67+`（后端统一 RFC 6750 Bearer 鉴权）
> 更新日期：2026-08-20
>
> 共用节点地址见 [`NODE_URLS.md`](./NODE_URLS.md)。

## 1. 鉴权模型（RFC 6750）

全系统**只有一种**鉴权方式：

```http
Authorization: Bearer <ACCESS_TOKEN>
```

- `ACCESS_TOKEN` 为全局共享令牌，环境变量或 `setting.json` 的 `access_token` 配置，优先级 env > setting.json
- **留空 = 全部开放**（匿名节点兼容行为）
- 比较使用常数时间算法（SHA-256 后 `subtle.ConstantTimeCompare`），防时序侧信道

已删除的旧机制（均不再可用）：

| 旧机制 | 现状 |
|---|---|
| `sk-ipw-` key 库（`node_keys.json`） | 已删除，旧 key 全部失效（401） |
| `IPW_ADMIN_TOKEN` + `/v1/admin/keys` 管理接口 | 已删除（404） |
| `X-IPW-Admin-Token` 请求头 | 已删除（401） |
| `IPW_SPEED_API_KEY_REQUIRED` 开关 | 已删除，speed 路由与其它查询路由同等保护 |
| 每节点独立 `_KEY` 环境变量 | 已删除，节点侧只认全局 `ACCESS_TOKEN` |

例外（wsmdn.top 外部节点）：深圳龙岗 / 四川沙渠 / 西安 [ZFC] 等上游节点由对方签发专用 key，主站 nginx 代理时注入，详见第 5 节。

## 2. 接口鉴权矩阵

| 接口 | 方法 | 鉴权 | 说明 |
|---|---|---|---|
| `/` | GET | 公开 | 健康检查 |
| `/v1/curl` | GET | 公开 | 出口 IP 回显 |
| `/api/v1/public-query/nodes` | GET | 公开 | 节点列表（限流 30/分/IP） |
| `/api/v1/public-query/:node/:probe` | POST | 公开 | 浏览器探测代理（限流+24 并发闸） |
| `/v1/detail/*url` | GET | **Bearer** | 网站检测 |
| `/v1/ssl/*url` | GET | **Bearer** | SSL 检查 |
| `/v1/tcping/:ip` | GET | **Bearer** | TCPing |
| `/v1/dns/:type/*domain` | GET | **Bearer** | DNS 解析 |
| `/v1/dnssec/:domain` | GET | **Bearer** | DNSSEC |
| `/v1/speed/:version/*url` | GET | **Bearer** | 网站测速 |
| `/v1/whois/:domain` | GET | **Bearer** | WHOIS |
| `/v1/asn/:ip` | GET | **Bearer** | ASN 查询 |
| `/v1/location/:ip` | GET | **Bearer** | IP 归属 |
| `/v1/location` | GET | **Bearer** | 自身 IP 归属 |
| `/v1/email-security/:domain` | GET | **Bearer** | SPF/DKIM/DMARC |
| `/v1/rbl/:ip` | GET | **Bearer** | RBL 黑名单 |
| `/v1/cdn/*url` | GET | **Bearer** | CDN 识别 |
| `/v1/security-headers/*url` | GET | **Bearer** | 安全头 |
| `/v1/ct-logs/:domain` | GET | **Bearer** | CT 日志 |
| `/v1/batch-location` | POST | **Bearer** | 批量 IP 归属 |
| `/v1/speedtest-payload` | GET | **Bearer** | 下载测速载荷 |
| `/v1/speedtest-upload` | POST | **Bearer** | 上传测速 |
| `/v1/http-test` | POST | **Bearer** | HTTP 探测 |
| `/v1/tcp-test` | POST | **Bearer** | TCP 探测 |
| `/v1/udp-test` | POST | **Bearer** | UDP 探测 |
| `/v1/traceroute` | POST | **Bearer** | 路由追踪 |
| `/v1/dns-query` | POST | **Bearer** | DNS 探测 |
| `/v1/dnssec-query` | POST | **Bearer** | DNSSEC 探测 |
| `/v1/asn` | POST | **Bearer** | ASN 探测 |
| `/v1/whois` | POST | **Bearer** | WHOIS 探测 |
| `/v1/email-security` | POST | **Bearer** | 邮件安全探测 |
| `/v1/rbl` | POST | **Bearer** | RBL 探测 |
| `/v1/cdn` | POST | **Bearer** | CDN 探测 |
| `/v1/security-headers` | POST | **Bearer** | 安全头探测 |

POST 探测族同时支持 `/v1/...` 与 `/api/v1/...` 两种前缀。
所有探测接口拒绝内网/回环/链路本地目标（SSRF 防护）。

## 3. 节点部署要点

```dotenv
# /opt/ipw-speed-node/data/node.env（0600）
PORTS=18080
BIND_ADDRESS=0.0.0.0
IPDB=false            # 纯测速节点不下 IP 库；归属查询节点才开
ACCESS_TOKEN=<令牌>   # 与主站一致；留空则该节点开放
```

- systemd unit `ipw-speed-node.service`，`EnvironmentFile` 指向上面的 env
- ARM 机器（华为云 devenv 等）需 `linux/arm64` 构建：`GOOS=linux GOARCH=arm64 go build`
- 双栈节点**不要**设 `SINGLE_STACK`；纯 v4 节点设 `SINGLE_STACK=ipv4` 跳过 v6 探测
- 需 `traceroute` 二进制（Ubuntu: `apt-get install traceroute`）

## 4. 主站注册节点

`public_query.go` 的 `configured` 表是编译时常量，新增节点两步：

1. 表里加 `{id, label, envPrefix}`，重新编译主站
2. 主站 env 加 `IPW_PUBLIC_NODE_<ID>_URL=http://node:18080`（`_KEY` 不再需要）

前端普通页面（测速/DNS/TCPing 列表）另需在 `src/nodes.ts` 定义 `SourceNode`
并在 `nginx` 加同源代理 location。

## 5. nginx 同源代理与鉴权注入

浏览器不直连节点，全部走主站同源路径，由 nginx 注入凭据：

```nginx
# 自有节点：统一令牌（0600，内容一行）
# /etc/nginx/snippets/ipw-backend-auth.conf
proxy_set_header Authorization "Bearer <ACCESS_TOKEN>";

# wsmdn.top 外部节点：对方签发的专用 key（0600）
# /etc/nginx/snippets/ipw-wsmdn-auth.conf
proxy_set_header Authorization "Bearer <WSMDN_KEY>";

location ^~ /example-node/ {
    proxy_pass http://node.example:18080/;
    proxy_http_version 1.1;
    include /etc/nginx/snippets/ipw-backend-auth.conf;   # 按节点类型选
    proxy_set_header Host $proxy_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-IPW-Client-IP $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_connect_timeout 4s;
    proxy_read_timeout 60s;
}
```

**snippet 文件永不入库**（`.gitignore` 覆盖 `/etc/nginx` 全部内容）；
key 只存在于服务器受限文件与双方私密交接渠道。

## 6. 当前节点清单

| 路径前缀 | 节点 | 栈 | 鉴权 snippet |
|---|---|---|---|
| `/jiangsu-node/` | 江苏 移动（wsmdn） | dual | 开放（对方未启用） |
| `/shenzhen-node/` | 深圳 龙岗 移动（wsmdn） | dual | wsmdn 专用 key |
| `/sichuan-node/` | 四川 沙渠 电信 [ZFC]（wsmdn） | v6 | wsmdn 专用 key |
| `/xian-node/` | 西安 电信 [ZFC]（wsmdn） | v4 | wsmdn 专用 key |
| `/guangzhou-node/` | 广州 腾讯云（wsmdn） | v4 | 开放 |
| `/singapore-node/` | 新加坡 腾讯云（wsmdn） | v4 | 开放 |
| `/hkcloudie-node/` | 香港 Cloudie [ZFC]（wsmdn） | v6 | 开放 |
| `/speed-node/` `/manage-node/zaozhuang/` | 山东 枣庄 双线 | v4 | 统一 token |
| `/shiyan-node/` | 湖北 十堰 电信 | v4 | 统一 token |
| `/hongkong2-node/` | 香港 VpsQuan | v4 | 统一 token |
| `/jdcloud-node/` | 北京 京东云 BGP | v4 | 统一 token |
| `/huawei-node/` | 华为云 北京（ARM） | v4 | 统一 token |
| `/tencent-sh-node/` | 上海 腾讯云 BGP | dual | 统一 token |
| `/xian2-node/` | 陕西 西安二 电信 | v4 | 统一 token |
| `/manage-node/hongkong/` | 香港 Cogent | v4 | 统一 token |

## 7. 验收清单

新节点上线后依次确认：

```bash
# 节点本机
curl http://127.0.0.1:18080/                                   # 200
curl -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18080/v1/speed/v4/1ipw.cn          # 401（无凭据）
curl -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN" \
     http://127.0.0.1:18080/v1/speed/v4/1ipw.cn                # 200

# 主站转发（public-query）
curl -X POST https://1ipw.cn/api/v1/public-query/<id>/tcp \
     -H 'Content-Type: application/json' \
     -d '{"host":"1.1.1.1","port":443}'                        # 200

# 同源代理（普通页面）
curl https://1ipw.cn/<id>-node/v1/dns/a/example.com            # 200
```

三项全 200 才算接入完成。
