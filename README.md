# acmebox

ACME（RFC 8555）证书申请工具：选 CA → 填域名 → DNS 验证 → 签发 → 下载证书。
密码学全部在本机完成：密钥生成、CSR、JWS 签名都用 Python `cryptography`，没有自研密码学。

**在线实例**：<https://ssl.167891.xyz/>（使用时请先读页面上的「使用须知」）

---

## 快速开始

```bash
pip install cryptography
python3 -m acmebox.app            # 打开 http://127.0.0.1:8787/
```

可选参数：

```bash
python3 -m acmebox.app --port 9000        # 换端口
python3 -m acmebox.app --token 你的口令   # 开启访问令牌
python3 -m acmebox.app --verbose          # 打印每个请求
```

默认只监听 `127.0.0.1`。要放公网先读「部署与安全」。

---

## 使用流程

1. **服务与密钥** —— 选 CA、填联系邮箱，生成证书密钥和账户密钥。
2. **域名** —— 填域名，支持通配符。
3. **验证** —— 页面列出每组 TXT 记录，到此步需你手动加到 DNS 服务商后台。
   等生效后点「开始验证」。
4. **证书** —— 签发完成，下载 cert.pem、key.pem，或导出「全部信息」。

### 支持的 CA

- Let's Encrypt（正式 / staging）
- ZeroSSL（需要 EAB：KID + HMAC KEY）
- Google Trust Services（需要 EAB）
- 任意自建 ACME v2 服务（手填目录 URL）

### 通配符的两个坑

1. `*.example.com` **不包含** `example.com`，两个都要就都填。
2. `*.a.com` 与 `a.com` 的 TXT 记录名相同，但**需要两个不同的值**，
   必须同时写入。界面会把它们列在一起。

---

## 续期

证书有效期 90 天，到期前用上次导出的「全部信息」文件续期即可。

**在第 1 步的「续期」区**：点「选择记录文件」载入 → 看到到期时间与建议
→ 点「一键续期」，直接跳到验证步骤。

**或在第 4 步**把 .json 拖进框里，效果相同。

续期的实质是重新签一张新证书。关键在于**账户私钥要沿用**：CA 认得它，
可能直接复用之前的域名验证结果，省去重新等 DNS 传播。换新账户则所有域名都要重验。

旧证书在新证书装好前可以继续用，不用急着删。

---

## 导出全部信息

第 4 步的「全部信息 (.json)」把一次申请的所有东西装进一个文件：

| 部分 | 内容 |
|---|---|
| `settings` | CA 名称与目录地址、邮箱、EAB 凭据、域名列表 |
| `keys` | 账户私钥、证书私钥，各附一句用途说明 |
| `certificate` | 证书正文（PEM）、有效期等信息、完整链、叶子证书与中间证书分开的副本 |
| `usage` | 续期怎么做、nginx / Apache 怎么配、手动填写时粘哪个字段、怎么拆证书链 |
| `warning` | 文件含明文私钥的提醒 |

页面上可以点「查看内容」直接预览，不必先下载。

**这个文件是明文私钥，按密码同样保管。** 给别人证书时只发 `certificate.pem` 字段，
不要给整个文件。

手动部署时用哪一段：

```
证书正文  → certificate.pem         → nginx: ssl_certificate
证书私钥  → keys.certificate_private_key → nginx: ssl_certificate_key
中间证书  → certificate.intermediates    → Apache: SSLCertificateChainFile
```

在其他机器上接着做：`keys.account_private_key` 粘进「导入已有」账户密钥，
`keys.certificate_private_key` 粘进证书私钥。都要完整 PEM，含首尾 `-----BEGIN/END-----`。

导出文件向后兼容：新版能读旧版格式，旧版字段平铺在顶层也能导入。

---

## 部署与安全

### 默认状态

- 只监听 `127.0.0.1`，外部访问不到。
- 不写任何文件：密钥、订单状态全在内存，进程退出即消失。
- 不开访问令牌也能用，因为只有本机能连。

### 放公网时

**必须做**：

1. **开访问令牌**，否则任何人都能拿你的机器申请证书。
   ```bash
   ACMEBOX_TOKEN=$(openssl rand -hex 24) python3 -m acmebox.app
   ```

2. **套一层 HTTPS 反向代理**。本服务只讲 HTTP，否则令牌和私钥明文过网。

   ```nginx
   server {
       listen 443 ssl http2;
       server_name ssl.example.com;

       ssl_certificate     /etc/letsencrypt/live/ssl.example.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/ssl.example.com/privkey.pem;

       # 每个域名验证最多等 180 秒，多域名串行累加，默认 60s 会先断
       proxy_read_timeout 600s;
       proxy_send_timeout 600s;
       client_max_body_size 1m;

       location / {
           proxy_pass http://127.0.0.1:8787;
           proxy_http_version 1.1;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

3. **限制来源**，用防火墙或反代限定 IP。

**已做到的防护**：ACME 目录 URL 只接受 https 并拒绝本机、内网与云元数据地址；
静态文件路径防穿越；请求体上限 512 KB；错误响应不带堆栈也不暴露 Python 版本。

**仍存在的风险**：

- 内存中的私钥和令牌对这个进程可见，同机其他不可信进程理论上能读到。
- 没有账号体系，令牌是唯一的门。
- 没有速率限制，公网暴露时请在前置代理上配。

---

## 项目结构

```
acmebox/
  __init__.py   包入口，导出协议核心
  acme.py       ACME v2 协议核心：JWS、nonce、订单、CSR
  app.py        HTTP 服务：路由、会话、记录导入导出、令牌鉴权
  web/          前端：index.html / style.css / app.js
requirements.txt
LICENSE          MIT
```

---

## 已知限制

- 只支持 DNS-01 与 HTTP-01，不实现 tls-alpn-01（需在 443 端口终止 TLS）。
- 不支持账户密钥轮换。
- **不自动写 DNS**，需要你手动添加 TXT 记录。这是有意的：避免工具持有你
  DNS 服务的写权限。
- 域名验证是串行的，域名越多越慢（单个通常 10–30 秒）。
- 证书不会自动续期，到期前手动用记录文件跑一次。

---

## 许可

[MIT](LICENSE)。ACME 按 RFC 8555 实现；密钥生成与签名使用 Python `cryptography`，
没有自研密码学。

使用风险自担：证书与私钥由本工具在内存中生成与暂存，不写入磁盘，签发完成后
60 秒释放；部署在公网时请自己评估这个时间窗口带来的风险。
