# acmebox

ACME（RFC 8555）证书申请工具：选 CA → 填域名 → DNS 验证 → 签发 → 下载证书。
后端是 Python 标准库加 `cryptography`，前端是原生 HTML/CSS/JS，没有构建步骤。

**在线实例**：<https://ssl.167891.xyz/>（首次打开会弹「使用须知」，建议先读）
**源码**：本仓库，MIT 许可

---

## 快速开始

要求 Python 3.10+，只需一个第三方包：

```bash
pip install -r requirements.txt
python3 -m acmebox.app            # 打开 http://127.0.0.1:8787/
```

在仓库根目录执行即可（包目录就在旁边）。

可选参数：

```bash
python3 -m acmebox.app --port 9000        # 换端口
python3 -m acmebox.app --token 你的口令   # 开启访问令牌
python3 -m acmebox.app --host 0.0.0.0     # 换监听地址，放公网前先读下文
python3 -m acmebox.app --verbose          # 打印每个请求（不含请求体）
```

默认只监听 `127.0.0.1`。

---

## 使用流程

页面顶部是四个步骤加一个独立入口：

```
1 密钥 · 2 域名 · 3 验证 · 4 证书 · 续期
```

1. **服务与密钥** —— 选 CA、填联系邮箱，生成证书私钥和账户私钥。
2. **域名** —— 一行一个或用逗号分隔，支持通配符。
3. **验证** —— 列出需要添加的 TXT 记录，手动加到 DNS 服务商后台，生效后点「开始验证」。
4. **证书** —— 签发完成，下载 `cert.pem`、`key.pem`，或保存「全部信息」记录文件。
5. **续期** —— 与四步并列的独立入口，导入上次的记录文件即可，详见下文。

### 支持的 CA

- Let's Encrypt（正式 / 测试环境）
- ZeroSSL（需要 EAB：KID + HMAC KEY）
- Google Trust Services（需要 EAB）
- 任意自建 ACME v2 服务（手填目录 URL，只接受 https 且拒绝本机与内网地址）

列表第一项是正式环境，会占用该域名的签发额度；只想演练请选「测试环境」，
它签出的证书不被浏览器信任。

### 通配符的两个坑

1. `*.example.com` **不包含** `example.com`，两个都要就都填。
2. `*.a.com` 与 `a.com` 的 TXT 记录名相同，但**需要两个不同的值**，必须同时写入。
   界面会把它们列在一起。

---

## 续期

证书 90 天有效，到期前用上次导出的记录文件续一次即可。

1. 点顶部「续期」标签；
2. 拖入或粘贴上次的 `.json`——**不用先导入就能看到里面的证书信息**（域名、到期时间、剩余天数）；
3. 点「一键续期」，确认后直接进入验证步骤；记录里没有账户私钥时会先走导入。

续期的实质是带着原来的账户私钥重签一张。同一账户的域名验证由 CA 保留一段
时间（Let's Encrypt 为 30 天），期内不需要重新加 DNS 记录；换新账户或超过保留期，
就要重新验证。旧证书在新证书装好前可以继续用。

---

## 导出全部信息

第 4 步的「全部信息 (.json)」把一次申请的所有东西装进一个文件：

| 部分 | 内容 |
|---|---|
| `settings` | CA 名称与目录地址、邮箱、EAB 凭据、域名列表 |
| `keys` | 账户私钥、证书私钥，各附一句用途说明 |
| `certificate` | 证书正文（PEM）、签发者与有效期、完整链、叶子与中间证书分开的副本 |
| `usage` | 续期怎么做、nginx / Apache 怎么配、手动填写时粘哪个字段、怎么拆链 |
| `warning` | 文件含明文私钥的提醒 |

有效期与签发者按**北京时间（UTC+8）**显示。

**这个文件是明文私钥，按密码同样保管。** 只把证书给别人时，用 `certificate.pem`
字段，不要给整个文件。

手动部署时用哪一段：

```
证书正文  → certificate.pem                 → nginx: ssl_certificate
证书私钥  → keys.certificate_private_key    → nginx: ssl_certificate_key
中间证书  → certificate.intermediates       → Apache: SSLCertificateChainFile
```

换机器接着做：`keys.account_private_key` 粘进「导入已有」账户密钥，
`keys.certificate_private_key` 粘进证书私钥，都要完整 PEM（含首尾 `-----BEGIN/END-----`）。

导出文件向后兼容：新版能读旧版格式，旧字段平铺在顶层也能导入。

---

## 隐私与信任（重要）

服务端**不写任何文件**，但为了完成签发，证书私钥必须短暂经过服务进程的内存：

- 签发完成后 **60 秒**删除整份会话；未完成的会话空闲 **10 分钟**过期，后台每 30 秒清扫一次。
- 删除只是解引用，Python 不会擦除那块内存，残留字节可能在被复用前仍然存在。
- 部署时请关掉核心转储（`ulimit -c 0`，或 systemd 的 `LimitCORE=0`）：否则进程崩溃
  产生的 core 文件可能带着私钥。在线实例的启动脚本已经这样做了。
- 请求体从不写入日志。
- 同一台主机上的其他用户读不到这个进程的内存（按 uid 隔离）；**主机 root 与托管服务商可以**。
- 服务运营者掌握代码与进程，理论上有能力读取这段内存。不能接受这一点就自己部署。

在线实例把这条写进了「使用须知」，首次访问时展示。

---

## 部署到公网

默认只监听 `127.0.0.1`，本机自己用不需要任何额外配置。放公网时：

1. **套一层 HTTPS 反向代理**。服务本身只讲 HTTP，直接暴露会让私钥明文过网。

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

2. **按需开访问令牌**（`--token` 或环境变量 `ACMEBOX_TOKEN`）。开了之后每个 `/api`
   请求都要带 `X-AcmeBox-Token`，页面会提示输入。是否开启取决于你把它当公共工具
   还是私人工具。

3. **限制来源**：用防火墙或反代限定 IP，并在前置代理上加速率限制——服务本身没有。

**已内建的防护**：ACME 目录 URL 只接受 https，拒绝本机、内网与云元数据地址（防 SSRF）；
静态文件路径防穿越；请求体上限 512 KB；错误响应不带堆栈、不暴露 Python 版本。

**用守护进程托管**（systemd 示例）：

```ini
[Unit]
Description=acmebox
After=network-online.target

[Service]
WorkingDirectory=/opt/acmebox
LimitCORE=0
ExecStart=/opt/acmebox/venv/bin/python -m acmebox.app --port 8787
Restart=on-failure
User=acmebox
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

内存态意味着重启会丢掉未导出的密钥和订单，重启前先把「全部信息」存下来。

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
- **不自动写 DNS**，TXT 记录需要你手动添加。这是有意的：避免工具持有你 DNS
  服务商的写权限。
- 域名验证串行执行，域名越多越慢（单个通常 10–30 秒）。
- 证书不会自动续期，到期前手动用记录文件跑一次。
- 没有账号体系；公网实例靠访问令牌或前置代理做门禁。

---

## 许可

[MIT](LICENSE)。ACME 按 RFC 8555 实现；密钥生成与签名使用 Python `cryptography`，
没有自研密码学。

使用风险自担：证书与私钥在服务进程内存中生成并暂存，签发完成后 60 秒释放。
