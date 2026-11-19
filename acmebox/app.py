"""acmebox 本地服务：在 ACME 核心外面套一层很小的 HTTP API。

状态只在内存里，进程退出即消失，本模块不写任何文件；运营者凭据不内置，访问令牌可
选（环境变量 ``ACMEBOX_TOKEN``），默认只监听 127.0.0.1。

CA 目录地址由用户输入，因此强制 https 且拒绝本机/内网地址，避免变成 SSRF 跳板。
"""

from __future__ import annotations

import argparse
import datetime
import json
import mimetypes
import os
import secrets
import socket
import threading
import time
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from . import acme

VERSION = acme.VERSION
SESSION_TTL = 6 * 3600          # 未完成的会话在内存里留六小时
CERT_GRACE = 60                 # 证书签发后 60 秒就释放：用户已经拿到，要续期可再导入
SWEEP_INTERVAL = 30             # 后台回收线程的节拍
MAX_BODY = 512 * 1024           # 用户会整段贴回 PEM，留宽一点
STATIC_ROOT = Path(__file__).resolve().parent / "web"

_sessions: dict[str, dict] = {}
_sessions_lock = threading.Lock()


# --------------------------------------------------------------------------- #
# 会话存储
# --------------------------------------------------------------------------- #


class Session:
    """每个访客的独立状态；进程退出即全部消失。"""

    def __init__(self, sid: str):
        self.id = sid
        self.created = time.time()
        self.touched = time.time()
        self.lock = threading.Lock()
        # 账户与密钥
        self.directory_url: str = acme.KNOWN_DIRECTORIES["letsencrypt"]
        self.email: str | None = None
        self.eab_kid: str | None = None
        self.eab_hmac_key: str | None = None
        self.account_key: str | None = None
        self.cert_key: str | None = None
        # 订单状态
        self.domains: list[str] = []
        self.order_url: str | None = None
        self.authz_urls: list[str] = []
        self.plans: list[dict] = []
        self.certificate: str | None = None
        self.cert_info: dict | None = None
        # 下单会清掉 cert_info；上一张的摘要留一份，续期页面不至于突然空白
        self.previous_cert_info: dict | None = None
        self.completed_at: float | None = None
        self.client: acme.AcmeClient | None = None

    def touch(self) -> None:
        self.touched = time.time()

    def expired(self) -> bool:
        idle = time.time() - self.touched
        if self.completed_at and time.time() - self.completed_at > CERT_GRACE:
            return True
        return idle > SESSION_TTL

    def client_for_request(self) -> acme.AcmeClient:
        """设置没变就复用客户端，变了重建。复用才能保住 kid 和 nonce 缓存。"""
        if self.account_key is None:
            self.account_key = acme.generate_key("rsa", 2048)
        rebuild = (
            self.client is None
            or self.client.directory_url != self.directory_url
            or self.client.account_key_pem != self.account_key
            or self.client.contact_email != self.email
            or self.client.eab_kid != self.eab_kid
            or self.client.eab_hmac_key != self.eab_hmac_key
        )
        if rebuild:
            self.client = acme.AcmeClient(
                self.directory_url,
                account_key_pem=self.account_key,
                contact_email=self.email,
                eab_kid=self.eab_kid,
                eab_hmac_key=self.eab_hmac_key,
            )
        return self.client

    def public(self) -> dict:
        """浏览器端可见的字段；私钥永远不出现在这里。"""
        return {
            "id": self.id,
            "directory": self.directory_url,
            "email": self.email,
            "domains": self.domains,
            "has_account_key": bool(self.account_key),
            "account_thumbprint": (
                acme.jwk_thumbprint(acme.jwk_from_key(self.account_key))
                if self.account_key else None
            ),
            "cert_key_type": _key_kind(self.cert_key),
            "plans": self.plans,
            "certificate": self.cert_info,
            "expires_in": self.remaining_seconds(),
        }

    def remaining_seconds(self) -> int:
        """这份会话还能活多久。

        签发完成后实际是 60 秒宽限（CERT_GRACE），不是 SESSION_TTL；
        再把 6 小时报给前端就是在说假话。
        """
        left = SESSION_TTL - (time.time() - self.touched)
        if self.completed_at:
            left = min(left, CERT_GRACE - (time.time() - self.completed_at))
        return max(0, int(left))


def _key_kind(pem: str | None) -> str | None:
    if not pem:
        return None
    try:
        return acme.key_algorithm(pem)
    except ValueError:
        return "unknown"


def _bj_now() -> str:
    """记录文件里的时间统一写北京时间，不带时区歧义。"""
    bj = datetime.timezone(datetime.timedelta(hours=8))
    return datetime.datetime.now(bj).strftime("%Y-%m-%dT%H:%M:%S+08:00")


def _sweep() -> None:
    with _sessions_lock:
        for sid in [s for s, v in _sessions.items() if v.expired()]:
            del _sessions[sid]


def _reaper_loop() -> None:
    """没有请求时也要回收：否则空置的服务会一直抱着已经没用的私钥。"""
    while True:
        time.sleep(SWEEP_INTERVAL)
        try:
            _sweep()
        except Exception:  # noqa: BLE001 - 回收失败不能把线程弄死
            traceback.print_exc()


def get_session(sid: str | None, *, create: bool = False) -> Session:
    _sweep()
    with _sessions_lock:
        if sid and sid in _sessions:
            sess = _sessions[sid]
            sess.touch()
            return sess
        if not create:
            raise KeyError("session not found")
        sess = Session(secrets.token_hex(16))
        _sessions[sess.id] = sess
        return sess


# --------------------------------------------------------------------------- #
# 请求处理辅助
# --------------------------------------------------------------------------- #


class ApiError(Exception):
    def __init__(self, message: str, *, status: int = 400, detail=None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.detail = detail


# 只认字面量地址和几个固定名字，不做 DNS 解析：域名指向内网时拦不住。这一步
# 的目标是挡住手滑和现成的探测链，不追求完整的内网隔离。
def _host_is_private(host: str) -> bool:
    host = host.lower().strip("[]")
    if host in ("localhost", "localhost.localdomain") or host.endswith(".local"):
        return True
    try:
        ip = socket.inet_pton(socket.AF_INET, host)
        octets = list(ip)
        return (octets[0] in (10, 127) or (octets[0] == 192 and octets[1] == 168)
                or (octets[0] == 172 and 16 <= octets[1] <= 31)
                or (octets[0] == 169 and octets[1] == 254) or octets[0] == 0)
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return host in ("::1",) or host.startswith("fc") or host.startswith("fd") \
            or host.startswith("fe80")
    except OSError:
        return False


def check_directory_url(url: str) -> str:
    """目录地址是用户填的，只放行 https 且非本机/内网，别把它当内网探测通道。"""
    url = (url or "").strip()
    if not url:
        raise ApiError("请填写 ACME 服务目录地址")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ApiError("ACME 服务地址必须是 https://")
    host = parsed.hostname or ""
    if not host:
        raise ApiError("ACME 服务地址缺少主机名")
    if _host_is_private(host):
        raise ApiError("不允许指向本机或内网地址")
    return url


def _clean_domains(value) -> list[str]:
    try:
        return acme.normalize_domains(value)
    except ValueError as exc:
        raise ApiError(str(exc)) from exc


def _require(sess: Session, *attrs: str) -> None:
    missing = [a for a in attrs if not getattr(sess, a, None)]
    if missing:
        names = {"account_key": "账户私钥", "cert_key": "证书私钥",
                 "domains": "域名", "order_url": "订单", "certificate": "证书"}
        raise ApiError("这一步还缺少：" + "、".join(names.get(a, a) for a in missing))


# --------------------------------------------------------------------------- #
# API 接口
# --------------------------------------------------------------------------- #


def api_config(_body, _sess) -> dict:
    return {
        "version": VERSION,
        "directories": [
            {"id": "letsencrypt", "name": "Let's Encrypt",
             "url": acme.KNOWN_DIRECTORIES["letsencrypt"], "note": "90 天，支持通配符"},
            {"id": "letsencrypt-staging", "name": "Let's Encrypt 测试环境",
             "url": acme.KNOWN_DIRECTORIES["letsencrypt-staging"],
             "note": "不签发可信证书，仅用于演练"},
            {"id": "zerossl", "name": "ZeroSSL",
             "url": acme.KNOWN_DIRECTORIES["zerossl"], "note": "需要 EAB 凭据"},
            {"id": "google", "name": "Google Trust Services",
             "url": acme.KNOWN_DIRECTORIES["google"], "note": "需要 EAB 凭据"},
        ],
        "key_types": [
            {"id": "rsa2048", "name": "RSA 2048", "kind": "rsa", "bits": 2048},
            {"id": "rsa3072", "name": "RSA 3072", "kind": "rsa", "bits": 3072},
            {"id": "ecc256", "name": "ECC P-256", "kind": "ecc", "bits": 256},
            {"id": "ecc384", "name": "ECC P-384", "kind": "ecc", "bits": 384},
        ],
    }


def api_session(body, sess) -> dict:
    """创建或更新会话设置。

    和其他接口一样把结果放在 ``session`` 键下，前端只需处理一种形状。
    """
    if "directory" in body:
        sess.directory_url = check_directory_url(body["directory"])
    if "email" in body:
        email = (body.get("email") or "").strip()
        if email and ("@" not in email or " " in email):
            raise ApiError("联系邮箱格式不正确")
        sess.email = email or None
    if "eab_kid" in body or "eab_hmac_key" in body:
        # 先把「合并后的结果」算出来并校验，通过了才写入：被拒的半套 EAB 不能留在会话里。
        kid = ((body.get("eab_kid") if "eab_kid" in body else sess.eab_kid) or "").strip() or None
        key = ((body.get("eab_hmac_key") if "eab_hmac_key" in body
                else sess.eab_hmac_key) or "").strip() or None
        if bool(kid) != bool(key):
            raise ApiError("EAB KID 和 HMAC KEY 要么都填，要么都不填")
        sess.eab_kid, sess.eab_hmac_key = kid, key
    sess.client = None   # force rebind with new settings
    return {"session": sess.public()}


def api_key(body, sess) -> dict:
    """生成账户密钥或证书密钥。"""
    which = body.get("which", "cert")
    kind = body.get("kind", "rsa")
    bits = int(body.get("bits", 2048))
    try:
        pem = acme.generate_key(kind, bits)
    except ValueError as exc:
        raise ApiError(str(exc)) from exc
    if which == "account":
        sess.account_key = pem
        sess.client = None
    else:
        sess.cert_key = pem
    # 生成新密钥就是在准备下一单：不能让 60 秒回收把正在干的活一起收走
    sess.completed_at = None
    return {
        "which": which,
        "algorithm": acme.key_algorithm(pem),
        "public_key": _public_from_private(pem),
        "session": sess.public(),
    }


def _public_from_private(pem: str) -> str:
    from cryptography.hazmat.primitives import serialization
    key = acme.load_key(pem).public_key()
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def api_key_import(body, sess) -> dict:
    which = body.get("which", "cert")
    pem = (body.get("pem") or "").strip()
    if not pem:
        raise ApiError("请粘贴 PEM 私钥")
    try:
        acme.load_key(pem)
        alg = acme.key_algorithm(pem)
    except ValueError as exc:
        raise ApiError(str(exc)) from exc
    if which == "account":
        sess.account_key = pem
        sess.client = None
    else:
        sess.cert_key = pem
    sess.completed_at = None
    return {"which": which, "algorithm": alg, "session": sess.public()}


def api_account(body, sess) -> dict:
    client = sess.client_for_request()
    account = client.register()
    sess.account_key = client.account_key_pem
    return {
        "status": account.get("status"),
        "kid": client._kid,
        "thumbprint": acme.jwk_thumbprint(acme.jwk_from_key(sess.account_key)),
        "session": sess.public(),
    }


def api_order(body, sess) -> dict:
    sess.domains = _clean_domains(body.get("domains") or [])
    if not sess.email:
        raise ApiError("请先填写联系邮箱")
    client = sess.client_for_request()
    if not client._kid:
        client.register()
    order, authzs = client.order_and_wait_ready(sess.domains)
    sess.order_url = order.get("_url")
    sess.authz_urls = list(order.get("authorizations") or [])
    sess.plans = acme.dns01_plans(authzs, client.account_key_pem)
    sess.previous_cert_info = sess.cert_info
    sess.certificate = None
    sess.cert_info = None
    # 又开了一单就不是「已完成」了：别让 60 秒回收误伤正在进行的新流程
    sess.completed_at = None

    detail = []
    for authz in authzs:
        detail.append({
            "domain": acme.authz_display_name(authz),
            "status": authz.get("status"),
            "wildcard": bool(authz.get("wildcard")),
            "challenges": [c["type"] for c in authz.get("challenges", [])],
            "http01_token": next((c["token"] for c in authz.get("challenges", [])
                                  if c["type"] == "http-01"), None),
            "http01_content": (
                acme.http01_content(
                    next(c["token"] for c in authz["challenges"] if c["type"] == "http-01"),
                    client.account_key_pem,
                ) if any(c["type"] == "http-01" for c in authz.get("challenges", [])) else None
            ),
        })
    warning = None
    if any(d.startswith("*.") for d in sess.domains):
        base = {d[2:] for d in sess.domains if d.startswith("*.")}
        if not base & set(sess.domains):
            warning = ("通配符 *.x 不包含裸域 x，如需两者都在证书里，请把 x 也填上。")
    return {
        "status": order.get("status"),
        "order_url": sess.order_url,
        "authorizations": detail,
        "dns_plans": sess.plans,
        "warning": warning,
        "session": sess.public(),
    }


def api_verify(body, sess) -> dict:
    """让 CA 去验证，然后等每条授权落定。

    已 valid 的直接跳过，不要再 respond；invalid / expired 这类非 pending 状态也直
    接收下，好让调用方看到失败原因而不是干等。
    """
    _require(sess, "account_key", "order_url")
    client = sess.client_for_request()
    if not client._kid:
        client.register()

    results = []
    for url in sess.authz_urls:
        authz = client.get_authorization(url)
        name = acme.authz_display_name(authz)
        if authz.get("status") == "valid":
            results.append({"domain": name, "status": "valid", "skipped": True})
            continue
        if authz.get("status") != "pending":
            results.append({"domain": name, "status": authz.get("status"),
                            "error": authz.get("error")})
            continue
        challenge_type = body.get("challenge_type", "dns-01")
        challenge = next((c for c in authz.get("challenges", [])
                          if c["type"] == challenge_type), None)
        if challenge is None:
            results.append({"domain": name, "status": "error",
                            "error": f"该域名不支持 {challenge_type} 验证"})
            continue
        client.respond_challenge(challenge["url"])
        settled = client.poll_authorization(url, timeout=float(body.get("timeout", 180)))
        results.append({
            "domain": name,
            "status": settled.get("status"),
            "error": (settled.get("error") or {}).get("detail"),
        })
    ok = all(r["status"] == "valid" for r in results)
    return {"ok": ok, "authorizations": results, "session": sess.public()}


def api_finalize(body, sess) -> dict:
    _require(sess, "account_key", "order_url", "cert_key", "domains")
    client = sess.client_for_request()
    if not client._kid:
        client.register()
    csr = acme.make_csr(sess.cert_key, sess.domains)
    order = client.get_order(sess.order_url)
    if order.get("status") not in ("ready", "processing", "valid"):
        raise ApiError(
            f"订单当前状态是 {order.get('status')}，还不能签发。"
            "请先把域名验证全部通过。"
        )
    if order.get("status") != "valid":
        client.finalize(order, csr)
        order = client.poll_order(sess.order_url)
    if order.get("status") != "valid":
        raise ApiError(f"签发未完成（状态 {order.get('status')}）",
                       detail=order.get("error"))
    pem = client.download_certificate(order["certificate"])
    sess.certificate = pem
    sess.cert_info = acme.describe_certificate(pem)
    # 记下完成时间：前台已经在页面里拿到全文，服务端不需要一直抱着私钥
    sess.completed_at = time.time()
    return {
        "certificate": pem,
        "private_key": sess.cert_key,
        "info": sess.cert_info,
        "chain_length": len(acme.split_chain(pem)),
        "session": sess.public(),
    }


def api_inspect(body, _sess) -> dict:
    pem = (body.get("pem") or "").strip()
    if not pem:
        raise ApiError("请粘贴证书 PEM")
    try:
        info = acme.describe_certificate(pem)
    except Exception as exc:  # noqa: BLE001 - 用户提供的任意 PEM
        raise ApiError(f"无法解析这份证书：{exc}") from exc
    return {"info": info, "chain_length": len(acme.split_chain(pem))}


def api_log_export(body, sess) -> dict:
    """导出全部信息：一个文件装下填写过的每一项与生成物。

    两个用途：拖回页面就能继续续期，或者直接拿去手动部署证书与私钥。因为包含明文
    私钥，文件里自带醒目提示与填写指引。

    注意：响应层会给所有结果补一个 session 字段（给前端刷新状态用），下载文件时
    前端会把它去掉，见 app.js 的 stripInternal。
    """
    info = sess.cert_info or {}
    chain = acme.split_chain(sess.certificate) if sess.certificate else []

    return {
        "format": "acmebox-log",
        "version": 2,
        "created_at": _bj_now(),
        "warning": (
            "这个文件含账户私钥、证书私钥和证书正文，全为明文。"
            "请当密码一样保管：不要发到聊天工具、网盘或任何公开位置。"
            "要把证书给别人时，只发 certificate.pem 字段，别给整个文件。"
        ),

        "settings": {
            "ca_name": _ca_display_name(sess.directory_url),
            "directory_url": sess.directory_url,
            "email": sess.email,
            "eab_kid": sess.eab_kid,
            "eab_hmac_key": sess.eab_hmac_key,
            "domains": sess.domains,
        },

        "keys": {
            "account_private_key": sess.account_key,
            "certificate_private_key": sess.cert_key,
            "account_key_hint": (
                "账户私钥：只用于向 CA 证明你是同一个账户。续期时务必带上，"
                "CA 可能因此复用之前的域名验证，省去重新等 DNS。"
            ),
            "certificate_key_hint": (
                "证书私钥：部署时用这个，必须与证书配对。nginx 对应 ssl_certificate_key。"
            ),
        },

        "certificate": {
            "pem": sess.certificate,
            "info": info,
            "chain_blocks": len(chain),
            "leaf_only": chain[0] if chain else None,
            "intermediates": chain[1:] if len(chain) > 1 else [],
        },

        "usage": {
            "renew": ("续期：打开 acmebox，第 1 步点「选择记录文件」载入本文件，"
                      "再点「一键续期」。账户私钥会自动复用。"),
            "nginx": ("nginx：把 certificate.pem 存成 cert.pem，keys.certificate_private_key "
                      "存成 key.pem，然后配置：\n"
                      "  ssl_certificate     /path/cert.pem;\n"
                      "  ssl_certificate_key /path/key.pem;"),
            "apache": ("Apache：\n"
                       "  SSLCertificateFile      /path/cert.pem\n"
                       "  SSLCertificateKeyFile   /path/key.pem\n"
                       "  SSLCertificateChainFile /path/chain.pem   # 取 certificate.intermediates"),
            "manual_fill": ("手动填写：在别的机器上接着做时，把 keys.account_private_key "
                            "粘进「导入已有」账户密钥，把 keys.certificate_private_key "
                            "粘进证书私钥。两者都要完整的 PEM，含首尾 -----BEGIN/END----- 两行。"),
            "split_chain": ("拆链：certificate.pem 里第一个 CERTIFICATE 是域名证书，"
                            "后面依次为中间证书和根证书。部分服务商要求分开上传，"
                            "用 leaf_only 与 intermediates 两段即可。"),
            "file_note": "证书统一为 PEM 纯文本，Windows 下可把后缀改成 .crt 双击查看。",
        },

        "note": "此文件包含私钥，请妥善保存，不要上传到公开位置。",
    }


def _ca_display_name(url: str) -> str:
    labels = {
        "letsencrypt": "Let's Encrypt",
        "letsencrypt-staging": "Let's Encrypt 测试环境",
        "zerossl": "ZeroSSL",
        "google": "Google Trust Services",
    }
    for key, known in acme.KNOWN_DIRECTORIES.items():
        if known == url:
            return labels.get(key, key)
    return url


def _normalize_log(data) -> dict:
    """把记录文件拆成统一字段，供导入和只读预览共用。

    v1 把字段平铺在顶层，v2 分成 settings / keys / certificate 三块。只看 version
    判断，不靠「某个键在不在」去猜：残缺的 v2 若被当成 v1，会读到一堆 None 然后
    静默通过。
    """
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError as exc:
            raise ApiError(f"记录文件不是合法 JSON：{exc}") from exc
    if not isinstance(data, dict) or data.get("format") != "acmebox-log":
        raise ApiError("这不是 acmebox 导出的记录文件")

    if data.get("version", 1) >= 2:
        settings = data.get("settings") or {}
        keys = data.get("keys") or {}
        cert = data.get("certificate") or {}
        fields = {
            "directory": settings.get("directory_url"),
            "email": settings.get("email"),
            "eab_kid": settings.get("eab_kid"),
            "eab_hmac": settings.get("eab_hmac_key"),
            "domains": settings.get("domains"),
            "account_key": keys.get("account_private_key"),
            "cert_key": keys.get("certificate_private_key"),
            "cert_pem": cert.get("pem"),
            "cert_not_after": cert.get("not_after"),
        }
        if not any(v for k, v in fields.items() if k != "cert_not_after"):
            raise ApiError(
                "这个文件标的是 v2 格式，但 settings / keys / certificate "
                "三个部分都是空的，可能已损坏或被手工改过。"
            )
    else:
        fields = {
            "directory": data.get("directory"),
            "email": data.get("email"),
            "eab_kid": data.get("eab_kid"),
            "eab_hmac": data.get("eab_hmac_key"),
            "domains": data.get("domains"),
            "account_key": data.get("account_key"),
            "cert_key": data.get("cert_key"),
            "cert_pem": data.get("certificate"),
            "cert_not_after": data.get("not_after"),
        }
    return fields


def _renew_verdict(info: dict) -> tuple[str, bool]:
    """根据剩余天数给出一句建议，以及是否到了该续的时候。"""
    days = info.get("days_left", 0)
    if days > 30:
        return (f"证书还有 {days} 天到期，暂时不用续。建议到期前 30 天内再操作。", False)
    if days > 7:
        return (f"还有 {days} 天到期，可以续了。尽早做，避免到期当天出意外。", True)
    return (f"只剩 {days} 天，建议立即续期。", True)


def api_log_preview(body, sess) -> dict:
    """只读预览：解析记录文件并返回证书信息，不改动会话。

    用户手里只有一个 .json、只想先确认「这是哪张证书、还剩几天」时，不该为了看一
    眼就把包含私钥的整份文件导进当前会话。
    """
    fields = _normalize_log(body.get("log"))
    domains = _clean_domains(fields.get("domains")) if fields.get("domains") else []
    has_account_key = bool(fields.get("account_key"))

    cert_pem = fields.get("cert_pem")
    if not cert_pem:
        return {
            "has_certificate": False,
            "from_file": True,
            "domains": domains,
            "has_account_key": has_account_key,
            "advice": ("这个文件里没有证书正文，拿不到到期时间。"
                       "仍可用于续期——导入后按流程重新签发即可。"),
        }

    try:
        info = acme.describe_certificate(cert_pem)
    except Exception as exc:  # noqa: BLE001 - 任意非法 PEM
        raise ApiError(f"记录文件里的证书正文无法解析：{exc}") from exc

    advice, urgent = _renew_verdict(info)
    return {
        "has_certificate": True,
        "from_file": True,
        "days_left": info.get("days_left"),
        "not_after": info.get("not_after"),
        "not_before": info.get("not_before"),
        "issuer": info.get("issuer"),
        "domains": info.get("domains") or domains,
        "urgent": urgent,
        "advice": advice,
        "has_account_key": has_account_key,
    }


def api_log_import(body, sess) -> dict:
    """导入记录文件。同时支持 v1（扁平）与 v2（分区）两种结构。"""
    fields = _normalize_log(body.get("log"))
    directory = fields.get("directory")
    email = fields.get("email")
    eab_kid = fields.get("eab_kid")
    eab_hmac = fields.get("eab_hmac")
    domains = fields.get("domains")
    account_key = fields.get("account_key")
    cert_key = fields.get("cert_key")
    cert_pem = fields.get("cert_pem")

    if directory:
        sess.directory_url = check_directory_url(directory)
    sess.email = email or sess.email
    sess.eab_kid = eab_kid or None
    sess.eab_hmac_key = eab_hmac or None

    # 私钥先验证再存：坏 PEM 混进来会让后续每一步都失败，且难查
    if account_key:
        try:
            acme.load_key(account_key)
        except ValueError as exc:
            raise ApiError(f"记录文件里的账户私钥无法解析：{exc}") from exc
        sess.account_key = account_key
    if cert_key:
        try:
            acme.load_key(cert_key)
        except ValueError as exc:
            raise ApiError(f"记录文件里的证书私钥无法解析：{exc}") from exc
        sess.cert_key = cert_key

    if domains:
        sess.domains = _clean_domains(domains)
    if cert_pem:
        sess.certificate = cert_pem
        try:
            sess.cert_info = acme.describe_certificate(cert_pem)
        except Exception:  # noqa: BLE001 - 可能是别处来的 PEM
            sess.cert_info = None
    sess.client = None
    return {"imported": True, "session": sess.public()}


def api_renew_precheck(body, sess) -> dict:
    """判断当前证书是否该续，并说明依据。

    续期本质是重新走一遍申请，但有件事值得单独告诉用户：没有账户密钥时 CA 会当成
    新账户，所有域名都得重新验证，这也是这里要提示的。
    """
    info = sess.cert_info if sess else None
    renewing = False
    if not info and sess is not None:
        # 下单后旧证书会被清掉；续期过程中仍把上一张的摘要显示出来，
        # 否则刚导入的记录一刷新就变成「还没有记录文件」。
        info = sess.previous_cert_info
        renewing = bool(info)
    if not info:
        return {
            "has_certificate": False,
            "source": "session",
            "advice": "还没有记录文件。选一个或粘贴内容，可以先把里面的证书信息看清楚，"
                      "再决定要不要导入。",
        }
    days = info.get("days_left", 0)
    if days > 30:
        advice = f"证书还有 {days} 天到期，暂时不用续。建议到期前 30 天内再操作。"
        urgent = False
    elif days > 7:
        advice = f"还有 {days} 天到期，可以续了。尽早做，避免到期当天出意外。"
        urgent = True
    else:
        advice = f"只剩 {days} 天，建议立即续期。"
        urgent = True
    if renewing:
        advice = "正在续期：下面是上一张证书的信息，新证书签发后会替换。"
    return {
        "has_certificate": True,
        "renewing": renewing,
        "source": "session",
        "days_left": days,
        "not_after": info.get("not_after"),
        "domains": info.get("domains") or sess.domains,
        "urgent": urgent,
        "advice": advice,
        "has_account_key": bool(sess.account_key),
        "note": ("这次会用同一个账户密钥，CA 可能复用之前的域名验证结果，通常更快。"
                 if sess.account_key else
                 "没有账户密钥，续期时会注册一个新账户，所有域名都要重新验证。"),
    }


def api_session_delete(_body, sess) -> dict:
    with _sessions_lock:
        _sessions.pop(sess.id, None)
    return {"deleted": True}


ROUTES = {
    "/api/config": api_config,
    "/api/session": api_session,
    "/api/session/delete": api_session_delete,
    "/api/key": api_key,
    "/api/key/import": api_key_import,
    "/api/account": api_account,
    "/api/order": api_order,
    "/api/verify": api_verify,
    "/api/finalize": api_finalize,
    "/api/inspect": api_inspect,
    "/api/log/export": api_log_export,
    "/api/log/preview": api_log_preview,
    "/api/renew/precheck": api_renew_precheck,
    "/api/log/import": api_log_import,
}


# --------------------------------------------------------------------------- #
# HTTP 层
# --------------------------------------------------------------------------- #


class Handler(BaseHTTPRequestHandler):
    server_version = f"acmebox/{VERSION}"
    sys_version = ""          # 不对外暴露 Python 版本
    access_token: str | None = None
    verbose: bool = False

    # -- 输出 --------------------------------------------------------------- #

    # 响应里可能有私钥和证书：禁缓存、禁止 MIME 嗅探、不外带 Referer。
    def _send(self, status: int, body: bytes, content_type: str,
              extra_headers: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False).encode(),
                   "application/json; charset=utf-8")

    def _error(self, status: int, message: str, detail=None) -> None:
        body = {"error": message}
        if detail:
            body["detail"] = detail
        self._json(status, body)

    def log_message(self, fmt: str, *args) -> None:
        if self.verbose:
            # 查询串可能带敏感参数，日志里只留路径
            print(f"[{self.log_date_time_string()}] {self.command} {self.path.split('?')[0]} "
                  f"{args[1] if len(args) > 1 else ''}")

    # -- 访问令牌 ----------------------------------------------------------- #

    def _authorized(self) -> bool:
        if not self.access_token:
            return True
        supplied = self.headers.get("X-AcmeBox-Token", "")
        return secrets.compare_digest(supplied, self.access_token)

    # -- 静态文件 ----------------------------------------------------------- #

    def _serve_static(self, path: str) -> bool:
        rel = "index.html" if path in ("", "/") else path.lstrip("/")
        target = (STATIC_ROOT / rel).resolve()
        # resolve 之后必须仍在 web/ 下，否则 ../../ 就能读到工作区其余文件
        if STATIC_ROOT.resolve() not in target.parents and target != STATIC_ROOT.resolve():
            self._error(HTTPStatus.FORBIDDEN, "禁止访问")
            return True
        if not target.is_file():
            return False
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript",):
            ctype += "; charset=utf-8"
        self._send(HTTPStatus.OK, target.read_bytes(), ctype)
        return True

    # -- 各 HTTP 方法 ------------------------------------------------------- #

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]
        if path.startswith("/api/"):
            if not self._authorized():
                self._error(HTTPStatus.UNAUTHORIZED, "缺少或错误的访问令牌")
                return
            if path == "/api/health":
                self._json(HTTPStatus.OK, {"ok": True, "version": VERSION})
                return
            if path == "/api/config":
                self._json(HTTPStatus.OK, api_config({}, None))
                return
            if path == "/api/session":
                try:
                    sess = get_session(self.headers.get("X-AcmeBox-Session"))
                    self._json(HTTPStatus.OK, {"session": sess.public()})
                except KeyError:
                    self._json(HTTPStatus.OK, {"session": None})
                return
            self._error(HTTPStatus.NOT_FOUND, "没有这个接口")
            return
        if not self._serve_static(path):
            self._error(HTTPStatus.NOT_FOUND, "页面不存在")

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]
        if not path.startswith("/api/"):
            self._error(HTTPStatus.NOT_FOUND, "没有这个接口")
            return
        if not self._authorized():
            self._error(HTTPStatus.UNAUTHORIZED, "缺少或错误的访问令牌")
            return
        handler = ROUTES.get(path)
        if handler is None:
            self._error(HTTPStatus.NOT_FOUND, "没有这个接口")
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "请求体过大")
            return
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
            if not isinstance(body, dict):
                raise ValueError("body must be an object")
        except (json.JSONDecodeError, ValueError):
            self._error(HTTPStatus.BAD_REQUEST, "请求体不是合法的 JSON 对象")
            return

        try:
            sid = self.headers.get("X-AcmeBox-Session")
            create = path in ("/api/session", "/api/log/import", "/api/key", "/api/key/import")
            if path in ("/api/log/preview", "/api/renew/precheck"):
                # 这两个接口在没有会话时也要能用；有会话就看得到，但绝不为它们新建会话
                try:
                    sess = get_session(sid, create=False) if sid else None
                except KeyError:
                    sess = None
            else:
                sess = get_session(sid, create=create)
            result = handler(body, sess)
        except KeyError:
            self._error(HTTPStatus.NOT_FOUND, "会话已失效，请刷新页面重新开始")
            return
        except ApiError as exc:
            self._error(exc.status, exc.message, exc.detail)
            return
        except acme.AcmeError as exc:
            self._error(HTTPStatus.BAD_GATEWAY, str(exc), exc.problem or None)
            return
        except Exception as exc:  # noqa: BLE001 - 绝不把 traceback 抛给客户端
            traceback.print_exc()
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, f"服务内部错误：{type(exc).__name__}")
            return

        payload = dict(result) if isinstance(result, dict) else {"result": result}
        extra = {}
        if sess:
            # 会话 id 走响应头，正文里统一放一个 session 对象，不再重复一份 id。
            payload.setdefault("session", sess.public())
            extra["X-AcmeBox-Session"] = sess.id
        self._send(HTTPStatus.OK, json.dumps(payload, ensure_ascii=False).encode(),
                   "application/json; charset=utf-8", extra)


def serve(host: str = "127.0.0.1", port: int = 8787, token: str | None = None,
          verbose: bool = False) -> None:
    Handler.access_token = token
    Handler.verbose = verbose
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    threading.Thread(target=_reaper_loop, name="session-reaper", daemon=True).start()
    shown = f"http://{host}:{port}/"

    def say(text: str) -> None:
        # 强制 flush：在 systemd 或重定向输出下，缓冲会让启动地址迟迟不出现
        print(text, flush=True)

    say(f"acmebox {VERSION} 已启动： {shown}")
    if token:
        say("已启用访问令牌：页面首次打开会要求填写令牌。")
    if host not in ("127.0.0.1", "localhost", "::1"):
        say("注意：正在监听非本地地址，请确认访问控制与前置代理是安全的。")
    say("按 Ctrl+C 停止。所有密钥与令牌只存在内存中，不会写入磁盘。")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        httpd.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="acmebox", description="本地 ACME 证书申请服务（Let's Encrypt / ZeroSSL / Google）")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址，默认 127.0.0.1")
    parser.add_argument("--port", type=int, default=8787, help="监听端口，默认 8787")
    parser.add_argument("--token", default=os.environ.get("ACMEBOX_TOKEN"),
                        help="可选访问令牌；也可用环境变量 ACMEBOX_TOKEN")
    parser.add_argument("--verbose", action="store_true", help="打印每个请求")
    args = parser.parse_args(argv)
    if args.port < 1024:
        print("端口必须 >= 1024")
        return 2
    serve(args.host, args.port, args.token, args.verbose)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
