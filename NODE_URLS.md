# 1IPW.CN Shared Node URLs

This document is the shared, credential-free node address reference for the
self-hosted 1IPW.CN deployment. Authentication is not encoded in any URL.
All protected requests use the server-side shared `ACCESS_TOKEN` as:

```http
Authorization: Bearer <ACCESS_TOKEN>
```

## Direct Node URLs

| ID | Region / provider | Direct URL | Stack | Notes |
|---|---|---|---|---|
| `zaozhuang` | Shandong Zaozhuang mobile/telecom | `http://127.0.0.1:28080` | v4 | Main-site reverse tunnel |
| `hongkong` | Hong Kong Cogent | `http://38.76.205.197:18080` | v4 | Self-hosted node |
| `xian2` | Shaanxi Xian 2 Telecom | `http://103.236.70.18:10808` | v4 | Existing NAT/service entry |
| `shiyan` | Hubei Shiyan Telecom | `http://210.16.163.65:18080` | v4 | New service port; SSH is separate |
| `hongkong2` | Hong Kong VpsQuan | `http://156.245.244.133:18080` | v4 | New service host/port |
| `jdcloud` | Beijing JD Cloud BGP | `http://116.196.116.184:18080` | v4 | Self-hosted node |
| `huawei` | Huawei Cloud Beijing | `http://127.0.0.1:28081` | v4 | Main-site reverse tunnel; ARM64 |
| `tencent-sh` | Shanghai Tencent Cloud BGP | `http://124.223.14.110:18080` | dual | IPv4 and IPv6 |

The loopback URLs are intentional: they are reverse tunnels terminated on the
main site and are not public node addresses.

## Main-Site Same-Origin Paths

Browsers should use these same-origin paths rather than embedding node
credentials or calling private node addresses directly:

| Node | Same-origin path |
|---|---|
| Zaozhuang | `/speed-node/` or `/manage-node/zaozhuang/` |
| Hong Kong Cogent | `/manage-node/hongkong/` |
| Xian 2 | `/xian2-node/` |
| Shiyan | `/shiyan-node/` |
| Hong Kong VpsQuan | `/hongkong2-node/` |
| JD Cloud | `/jdcloud-node/` |
| Huawei Cloud | `/huawei-node/` |
| Tencent Shanghai | `/tencent-sh-node/` |

Example browser-side request:

```text
https://1ipw.cn/shiyan-node/v1/speed/v4/1ipw.cn
https://1ipw.cn/hongkong2-node/v1/speed/v4/1ipw.cn
```

## Public Query Proxy

The browser-facing proxy is public and rate-limited. It adds the shared Bearer
token on the server side before forwarding to a node:

```text
POST https://1ipw.cn/api/v1/public-query/<node-id>/speed
```

Example body:

```json
{
  "target": "1ipw.cn",
  "version": "v4"
}
```

## Operational Notes

- Do not add SSH ports, passwords, access tokens, or nginx snippet contents to
  this document.
- The service port is `18080` on direct nodes unless the table explicitly shows
  a main-site tunnel or an existing NAT entry.
- The legacy Hong Kong 2 address `156.245.244.237` and the legacy Shiyan
  service entry `210.16.163.65:10808` are no longer the active service URLs.
- After changing a URL, update both the main-site environment and the matching
  nginx same-origin location, then run `nginx -t` before reload.
