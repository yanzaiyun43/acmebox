"""ACME v2（RFC 8555）核心：密钥、JWS 签名、订单与挑战计算。

约束：只用标准库加 ``cryptography``；不碰数据库、不落盘——私钥以 PEM 字符串
交回调用方，存不存由上层决定。

刻意不做 tls-alpn-01（要占 443 终止 TLS）和账户密钥轮换。
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import http.client
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils as asym_utils
from cryptography.x509.oid import NameOID

VERSION = "1.1.0"

# 对外只报一个版本号：app、__init__ 和 UA 都从这里取，免得三处各写一份。
USER_AGENT = f"acmebox/{VERSION} (+local ACME client)"

# 界面下拉里展示的已知 CA 目录；按插入顺序展示。
KNOWN_DIRECTORIES = {
    "letsencrypt": "https://acme-v02.api.letsencrypt.org/directory",
    "letsencrypt-staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "zerossl": "https://acme.zerossl.com/v2/DV90",
    "google": "https://dv.acme-v02.api.pki.goog/directory",
}


class AcmeError(RuntimeError):
    """ACME 服务返回的错误，或协议层面的问题。

    ``problem`` 原样保留服务端的 problem document，便于上层把 type/detail
    一起交给用户；``__str__`` 优先展示 detail。
    """

    def __init__(self, message: str, *, problem: dict | None = None, status: int | None = None):
        super().__init__(message)
        self.problem = problem or {}
        self.status = status
        self.type = self.problem.get("type", "")

    def __str__(self) -> str:  # pragma: no cover - 仅用于展示
        detail = self.problem.get("detail")
        if detail:
            return f"{detail} ({self.type or self.status})"
        return super().__str__()


# --------------------------------------------------------------------------- #
# 编码工具
# --------------------------------------------------------------------------- #


def b64u(data: bytes) -> str:
    """base64url 且去掉补位等号；ACME 的每个二进制字段都要求这个形式。"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# 紧凑、无空格、键排序：JWK 指纹是对「重编码后的字节」求哈希，格式必须可复现。
def b64u_json(obj: Any) -> str:
    return b64u(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode())


def _pem_norm(pem: str) -> bytes:
    """容忍末尾缺换行或使用 CRLF 的 PEM，统一成单行尾换行。"""
    if isinstance(pem, bytes):
        pem = pem.decode("utf-8")
    return pem.strip().encode("utf-8") + b"\n"


# --------------------------------------------------------------------------- #
# 密钥
# --------------------------------------------------------------------------- #


def generate_key(kind: str = "rsa", bits: int = 2048) -> str:
    """生成私钥，返回 PKCS#8 PEM。

    ``kind`` 取 ``"rsa"`` 或 ``"ecc"``；ECC 下 ``bits`` 选曲线：256 为 P-256，
    384 为 P-384。不支持的组合直接报错，不悄悄降级到 P-256——否则用户拿到
    的是他不知道的曲线，后续签名算法也会跟着变。
    """
    kind = kind.lower()
    if kind == "rsa":
        if bits not in (2048, 3072, 4096):
            raise ValueError("RSA 位数只能是 2048 / 3072 / 4096")
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    elif kind in ("ecc", "ec", "ecdsa"):
        if bits not in (256, 384):
            raise ValueError("ECC 位数只能是 256（P-256）或 384（P-384）")
        curve = ec.SECP384R1() if bits == 384 else ec.SECP256R1()
        key = ec.generate_private_key(curve)
    else:
        raise ValueError(f"不支持的密钥类型: {kind}")
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def load_key(pem: str):
    try:
        return serialization.load_pem_private_key(_pem_norm(pem), password=None)
    except Exception as exc:  # noqa: BLE001 - 原文直接回给用户
        raise ValueError(f"无法解析私钥 PEM：{exc}") from exc


def key_algorithm(pem: str) -> str:
    """这把私钥必须用哪个 JWS alg 签名：RS256 / ES256 / ES384。"""
    key = load_key(pem)
    if isinstance(key, rsa.RSAPrivateKey):
        return "RS256"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        if isinstance(key.curve, ec.SECP384R1):
            return "ES384"
        if isinstance(key.curve, ec.SECP256R1):
            return "ES256"
        raise ValueError(f"不支持的椭圆曲线: {key.curve.name}")
    raise ValueError("只支持 RSA 或 ECDSA 私钥")


def jwk_from_key(pem: str) -> dict:
    """私钥对应的公开 JWK；JWS 保护头和 EAB 里放的就是它。"""
    key = load_key(pem)
    pub = key.public_key()
    numbers = pub.public_numbers()
    if isinstance(key, rsa.RSAPrivateKey):
        return {
            "e": b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
            "kty": "RSA",
            "n": b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        }
    if isinstance(key, ec.EllipticCurvePrivateKey):
        size = (numbers.curve.key_size + 7) // 8
        crv = {ec.SECP256R1: "P-256", ec.SECP384R1: "P-384"}.get(type(numbers.curve))
        if crv is None:
            raise ValueError("只支持 P-256 / P-384")
        return {
            "crv": crv,
            "kty": "EC",
            "x": b64u(numbers.x.to_bytes(size, "big")),
            "y": b64u(numbers.y.to_bytes(size, "big")),
        }
    raise ValueError("只支持 RSA 或 ECDSA 私钥")


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 指纹：对**规范化后的 JSON 字节**求 SHA-256。

    只取规定成员（RSA: e/kty/n，EC: crv/kty/x/y），键排序、无空白。注意哈希对象
    是 JSON 本身而不是它的 base64——搞错了照样得到一个像模像样的指纹，JWS 签名
    也照样能验过，但算出的 DNS-01 TXT 值与 CA 算的不一致，报错会说 "Incorrect
    TXT record" 并把你刚发布的那个值原样贴出来，很容易怀疑是 DNS 没生效。
    """
    if jwk["kty"] == "RSA":
        subset = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    else:
        subset = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    canonical = json.dumps(subset, sort_keys=True, separators=(",", ":")).encode()
    return b64u(hashlib.sha256(canonical).digest())


# JWS 要求 ECDSA 签名是定长的 r||s（P-256 各 32 字节，P-384 各 48 字节），
# 而 cryptography 产出的是 DER，必须拆出来重拼，否则服务端一律判签名非法。
def _sign(pem: str, data: bytes) -> bytes:
    key = load_key(pem)
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    size = 32 if isinstance(key.curve, ec.SECP256R1) else 48
    der = key.sign(data, ec.ECDSA(hashes.SHA256() if size == 32 else hashes.SHA384()))
    r, s = asym_utils.decode_dss_signature(der)
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def eab_hmac(eab_kid: str, hmac_key_b64: str, jwk: dict, url: str) -> dict:
    """构造 newAccount 用的 EAB 对象（HS256 签名，密钥由 CA 侧给出）。"""
    try:
        raw = base64.urlsafe_b64decode(hmac_key_b64.strip() + "=" * (-len(hmac_key_b64.strip()) % 4))
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"HMAC KEY 不是合法的 base64url：{exc}") from exc
    protected = b64u_json({"alg": "HS256", "kid": eab_kid.strip(), "url": url})
    payload = b64u_json(jwk)
    signature = base64.urlsafe_b64encode(
        __import__("hmac").new(raw, f"{protected}.{payload}".encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    return {"protected": protected, "payload": payload, "signature": signature}


# --------------------------------------------------------------------------- #
# 域名与挑战
# --------------------------------------------------------------------------- #


def normalize_domains(raw: str | Iterable[str]) -> list[str]:
    """拆分、去空白、转小写、去重，并做基本合法性检查。

    用户常把网址整段粘进来，所以顺手剥掉 scheme、路径和末尾的点；通配符只允许
    出现在最左标签，``a.*.com`` 这类在 CA 侧必然失败，早点拦住。
    """
    if isinstance(raw, str):
        items = raw.replace("\n", ",").replace("，", ",").split(",")
    else:
        items = list(raw)
    out: list[str] = []
    for item in items:
        name = item.strip().lower().rstrip(".")
        if not name:
            continue
        if name.startswith("http://"):
            name = name[7:]
        if name.startswith("https://"):
            name = name[8:]
        name = name.split("/")[0]
        if name not in out:
            out.append(name)
    if not out:
        raise ValueError("至少要填一个域名")
    for name in out:
        label = name[2:] if name.startswith("*.") else name
        if "*" in label:
            raise ValueError(f"通配符只能出现在最左侧标签：{name}")
        if "." not in label or len(label) > 253 or len(name) > 259:
            raise ValueError(f"域名格式不正确：{name}")
        for part in label.split("."):
            if not part or len(part) > 63:
                raise ValueError(f"域名格式不正确：{name}")
    return out


def http01_content(token: str, account_key_pem: str) -> str:
    """key authorization：``token.thumbprint``，HTTP-01 要放到路径上的内容。"""
    return f"{token}.{jwk_thumbprint(jwk_from_key(account_key_pem))}"


def dns01_record_name(domain: str) -> str:
    """DNS-01 的 TXT 记录名；通配符去掉 ``*.`` 用父域，与裸域共用同一条记录。"""
    base = domain[2:] if domain.startswith("*.") else domain
    return f"_acme-challenge.{base}"


def dns01_value(token: str, account_key_pem: str) -> str:
    """TXT 记录的值：key authorization 的 SHA-256，再做 base64url。"""
    keyauth = http01_content(token, account_key_pem)
    return b64u(hashlib.sha256(keyauth.encode()).digest())


def authz_display_name(authz: dict) -> str:
    """授权的可读名字。

    服务端会把通配符的 ``*.`` 去掉、改成 ``wildcard: true``，只看 identifier 就
    分不清 ``*.a.com`` 和 ``a.com`` 是两条独立授权，而它们要的是不同的 TXT 值。
    """
    value = authz.get("identifier", {}).get("value", "")
    if authz.get("wildcard") and not value.startswith("*."):
        return f"*.{value}"
    return value


def dns01_plans(authzs: list[dict], account_key_pem: str) -> list[dict]:
    """把 DNS-01 要求按记录名归组。

    ``*.a.com`` 和 ``a.com`` 共用一条 TXT 记录却需要**不同**的值，同一条记录上
    会挂多个值；不归组的话调用方逐个写入时会互相覆盖。
    """
    plans: dict[str, dict] = {}
    for authz in authzs:
        name = dns01_record_name(authz_display_name(authz))
        challenge = next(
            (c for c in authz.get("challenges", []) if c["type"] == "dns-01"), None
        )
        if challenge is None:
            continue
        plan = plans.setdefault(name, {"name": name, "values": [], "authorizations": []})
        value = dns01_value(challenge["token"], account_key_pem)
        if value not in plan["values"]:
            plan["values"].append(value)
        plan["authorizations"].append(authz_display_name(authz))
    return list(plans.values())


def make_csr(key_pem: str, domains: list[str], *, country: str | None = None) -> bytes:
    """生成 CSR（DER）：所有域名进 SAN，第一个同时作 CN。

    CN 只取前 64 个字符、仅供兼容老客户端；域名集合以 SAN 为准。
    """
    key = load_key(key_pem)
    names = list(domains)
    subject = [x509.NameAttribute(NameOID.COMMON_NAME, names[0][:64])]
    if country:
        subject.insert(0, x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name(subject))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
    )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


# --------------------------------------------------------------------------- #
# HTTP 传输
# --------------------------------------------------------------------------- #


@dataclass
class AcmeResponse:
    status: int
    headers: dict
    body: bytes

    def json(self) -> Any:
        if not self.body:
            return None
        try:
            return json.loads(self.body)
        except json.JSONDecodeError:
            raise AcmeError(f"服务端返回了非 JSON 内容: {self.body[:200]!r}", status=self.status)

    def pem(self) -> str:
        return self.body.decode("utf-8", "replace")


# 不跟随 3xx：urllib 会把重定向的 POST 降级成 GET 并丢掉 JWS 请求体，或者把带
# 签名的请求重发到别处，两种都会得到一个看不懂的协议错误。
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


@dataclass
class AcmeClient:
    """一次会话内的 ACME 客户端：持有账户密钥、JWS 身份（jwk/kid）与 nonce 缓存。"""

    directory_url: str
    account_key_pem: str | None = None
    contact_email: str | None = None
    eab_kid: str | None = None
    eab_hmac_key: str | None = None
    timeout: int = 45
    log: list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.account_key_pem = self.account_key_pem or generate_key("rsa", 2048)
        self._jwk = jwk_from_key(self.account_key_pem)
        self._thumb = jwk_thumbprint(self._jwk)
        self._alg = key_algorithm(self.account_key_pem)
        self._nonce: str | None = None
        self._kid: str | None = None
        self._directory: dict | None = None
        self._opener = urllib.request.build_opener(_NoRedirect())

    # -- 底层：HTTP 与签名 -------------------------------------------------- #

    # 只留最近 500 条，长会话里轨迹够用，又不至于把内存耗在日志上。
    def _note(self, kind: str, **extra) -> None:
        entry = {"at": time.time(), "kind": kind, **extra}
        self.log.append(entry)
        if len(self.log) > 500:
            del self.log[:-500]

    def _request(self, method: str, url: str, body: bytes | None = None,
                 headers: dict | None = None, retries: int = 3) -> AcmeResponse:
        """一次 HTTP 往返，对瞬时网络错误做有限重试。

        移动网络常在半路断连；重试**签名过的**请求是安全的，因为每次尝试都由
        调用方用新 nonce 重新签名。HTTPError 不重试：那是服务端的明确答复。
        """
        last_exc: Exception | None = None
        for attempt in range(retries + 1):
            req = urllib.request.Request(url, data=body, method=method)
            req.add_header("User-Agent", USER_AGENT)
            for k, v in (headers or {}).items():
                req.add_header(k, v)
            try:
                with self._opener.open(req, timeout=self.timeout) as resp:
                    out = AcmeResponse(resp.status, dict(resp.headers), resp.read())
                break
            except urllib.error.HTTPError as exc:
                out = AcmeResponse(exc.code, dict(exc.headers), exc.read() or b"")
                break
            except urllib.error.URLError as exc:
                last_exc = exc
                if attempt == retries:
                    raise AcmeError(f"无法连接 ACME 服务：{exc.reason}") from exc
            except (http.client.HTTPException, OSError) as exc:
                last_exc = exc
                if attempt == retries:
                    raise AcmeError(f"连接 ACME 服务时网络中断：{exc}") from exc
            time.sleep(1.2 * (attempt + 1))
        else:  # pragma: no cover - 循环只会 break 或 raise
            raise AcmeError(f"无法连接 ACME 服务：{last_exc}")
        if out.headers.get("Replay-Nonce"):
            self._nonce = out.headers["Replay-Nonce"]
        return out

    # nonce 是一次性的：取走即清空，否则同一个值会被复用而被判 badNonce。
    def _fresh_nonce(self, *, force: bool = False) -> str:
        if self._nonce and not force:
            nonce, self._nonce = self._nonce, None
            return nonce
        resp = self._request("HEAD", self.directory["newNonce"])
        nonce = resp.headers.get("Replay-Nonce")
        if not nonce:
            raise AcmeError("ACME 服务没有返回 Replay-Nonce")
        return nonce

    def _signed(self, url: str, payload: Any, *, use_jwk: bool = False,
                headers: dict | None = None, retries: int = 2) -> AcmeResponse:
        """发一个扁平化 JWS。``payload is None`` 即 RFC 8555 的 POST-as-GET。

        未拿到 kid 时（注册前）必须用 jwk 而不是 kid 标识自己，这是协议硬要求。
        """
        last: AcmeError | None = None
        for attempt in range(retries + 1):
            # badNonce 的响应本身带了一个新 Replay-Nonce，_request 已经存下，
            # 所以重试直接复用它，省掉一次 HEAD 取 nonce 的往返。
            nonce = self._fresh_nonce()
            protected = {"alg": self._alg, "nonce": nonce, "url": url}
            if use_jwk or not self._kid:
                protected["jwk"] = self._jwk
            else:
                protected["kid"] = self._kid
            p64 = b64u_json(protected)
            payload64 = "" if payload is None else b64u_json(payload)
            sig = b64u(_sign(self.account_key_pem, f"{p64}.{payload64}".encode()))
            body = json.dumps({"protected": p64, "payload": payload64, "signature": sig}).encode()
            hdrs = {"Content-Type": "application/jose+json"}
            hdrs.update(headers or {})
            resp = self._request("POST", url, body, hdrs)
            if resp.status == 400 and b"badNonce" in (resp.body or b""):
                last = AcmeError("badNonce", status=400)
                continue
            if resp.status >= 400:
                problem = {}
                try:
                    problem = resp.json() or {}
                except AcmeError:
                    pass
                raise AcmeError("ACME 请求失败", problem=problem, status=resp.status)
            return resp
        raise last or AcmeError("ACME 请求失败")

    # -- 目录与账户 --------------------------------------------------------- #

    # 懒加载并缓存；缺 newAccount/newOrder/newNonce 说明这不是 ACME v2 目录，
    # 在这里报错比后面各处 KeyError 好查。
    @property
    def directory(self) -> dict:
        if self._directory is None:
            resp = self._request("GET", self.directory_url, headers={"Accept": "application/json"})
            if resp.status >= 400:
                raise AcmeError("无法读取 ACME 服务目录", status=resp.status)
            self._directory = resp.json() or {}
            for key in ("newAccount", "newOrder", "newNonce"):
                if key not in self._directory:
                    raise AcmeError(f"服务目录缺少 {key}，可能不是 ACME v2 服务")
        return self._directory

    def register(self, *, terms_agreed: bool = True) -> dict:
        """注册或取回账户，记下 kid，返回账户对象。

        newAccount 对已存在的账户不报错而是原样返回，所以重复调用是安全的。
        联系方式只在填了邮箱时才提交，空 contact 会被部分 CA 拒掉。
        """
        payload: dict[str, Any] = {"termsOfServiceAgreed": terms_agreed}
        if self.contact_email:
            email = self.contact_email.strip()
            payload["contact"] = [f"mailto:{email}" if ":" not in email else email]
        if self.eab_kid and self.eab_hmac_key:
            payload["externalAccountBinding"] = eab_hmac(
                self.eab_kid, self.eab_hmac_key, self._jwk, self.directory["newAccount"]
            )
        resp = self._signed(self.directory["newAccount"], payload, use_jwk=True)
        account = resp.json() or {}
        self._kid = resp.headers.get("Location") or account.get("url")
        if not self._kid:
            raise AcmeError("注册账户后没有拿到账户 URL")
        self._note("register", kid=self._kid, status=account.get("status"))
        return account

    def update_contact(self, email: str) -> dict:
        self._require_kid()
        resp = self._signed(self._kid, {"contact": [f"mailto:{email}"]})
        return resp.json() or {}

    def _require_kid(self) -> None:
        if not self._kid:
            raise AcmeError("账户尚未注册，请先调用 register()")

    # -- 订单 --------------------------------------------------------------- #

    def new_order(self, domains: list[str]) -> dict:
        self._require_kid()
        identifiers = [{"type": "dns", "value": d} for d in domains]
        resp = self._signed(self.directory["newOrder"], {"identifiers": identifiers})
        order = resp.json() or {}
        order["_url"] = resp.headers.get("Location")
        self._note("newOrder", domains=domains, status=order.get("status"))
        return order

    def get_order(self, url: str) -> dict:
        resp = self._signed(url, None)
        order = resp.json() or {}
        order["_url"] = url
        return order

    def get_authorization(self, url: str) -> dict:
        resp = self._signed(url, None)
        authz = resp.json() or {}
        authz["_url"] = url
        return authz

    def get_challenge(self, url: str) -> dict:
        resp = self._signed(url, None)
        ch = resp.json() or {}
        ch["_url"] = url
        return ch

    def respond_challenge(self, url: str) -> dict:
        resp = self._signed(url, {})
        ch = resp.json() or {}
        ch["_url"] = url
        return ch

    def deactivate_authorization(self, url: str) -> dict:
        resp = self._signed(url, {"status": "deactivated"})
        return resp.json() or {}

    def poll_authorization(self, url: str, *, timeout: float = 180.0,
                           interval: float = 2.0) -> dict:
        deadline = time.time() + timeout
        delay = interval
        while True:
            authz = self.get_authorization(url)
            status = authz.get("status")
            if status in ("valid", "invalid", "deactivated", "expired", "revoked"):
                return authz
            if time.time() >= deadline:
                raise AcmeError(f"等待域名验证超时（当前状态 {status}）")
            time.sleep(delay)
            delay = min(delay * 1.5, 6.0)

    def finalize(self, order: dict, csr_der: bytes) -> dict:
        url = order.get("finalize")
        if not url:
            raise AcmeError("订单里没有 finalize 地址")
        resp = self._signed(url, {"csr": b64u(csr_der)})
        out = resp.json() or {}
        out["_url"] = order.get("_url")
        self._note("finalize", status=out.get("status"))
        return out

    def poll_order(self, url: str, *, timeout: float = 180.0, interval: float = 2.0) -> dict:
        deadline = time.time() + timeout
        delay = interval
        while True:
            order = self.get_order(url)
            status = order.get("status")
            if status in ("valid", "invalid"):
                return order
            if time.time() >= deadline:
                raise AcmeError(f"等待签发超时（当前状态 {status}）")
            time.sleep(delay)
            delay = min(delay * 1.5, 6.0)

    def download_certificate(self, cert_url: str) -> str:
        """取回 PEM 证书链：叶子证书在前，中间证书依次在后。"""
        resp = self._signed(
            cert_url, None, headers={"Accept": "application/pem-certificate-chain"}
        )
        pem = resp.pem()
        if "BEGIN CERTIFICATE" not in pem:
            raise AcmeError("证书下载结果不是 PEM 格式")
        return pem

    def revoke(self, cert_pem: str, *, reason: int = 0) -> None:
        if "revokeCert" not in self.directory:
            raise AcmeError("该服务不支持吊销证书")
        der = x509.load_pem_x509_certificate(_pem_norm(cert_pem)).public_bytes(
            serialization.Encoding.DER
        )
        payload = {"certificate": b64u(der)}
        if reason:
            payload["reason"] = reason
        self._signed(self.directory["revokeCert"], payload)
        self._note("revoke", reason=reason)

    # -- 组合操作 ----------------------------------------------------------- #

    def order_and_wait_ready(self, domains: list[str]) -> tuple[dict, list[dict]]:
        """下单，并把订单和它当前的各条授权一起取回。"""
        order = self.new_order(domains)
        authz = [self.get_authorization(u) for u in order.get("authorizations", [])]
        return order, authz


def describe_certificate(pem: str) -> dict:
    """叶子证书的可读摘要，供界面展示。"""
    cert = x509.load_pem_x509_certificate(_pem_norm(pem))
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []

    # 旧版 cryptography 返回不带时区的 UTC 时间，新版带 tzinfo，统一补齐。
    def _utc(dt):
        return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)

    not_before, not_after = _utc(cert.not_valid_before), _utc(cert.not_valid_after)
    # 证书本身存的是 UTC；给用户看的统一换成北京时间（UTC+8）
    bj = datetime.timezone(datetime.timedelta(hours=8))
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": not_before.astimezone(bj).strftime("%Y-%m-%d %H:%M"),
        "not_after": not_after.astimezone(bj).strftime("%Y-%m-%d %H:%M"),
        "timezone": "Asia/Shanghai (UTC+8)",
        "serial": format(cert.serial_number, "x"),
        "domains": names,
        "days_left": max(0, (not_after - datetime.datetime.now(datetime.timezone.utc)).days),
    }


def split_chain(pem: str) -> list[str]:
    """把 PEM 包拆成单独的证书文本，保留 BEGIN/END 两行。"""
    blocks, cur = [], []
    for line in pem.splitlines():
        if "BEGIN CERTIFICATE" in line:
            cur = [line]
        elif cur:
            cur.append(line)
            if "END CERTIFICATE" in line:
                blocks.append("\n".join(cur) + "\n")
                cur = []
    return blocks


if __name__ == "__main__":  # 本地自检，不联网
    k = generate_key("rsa", 2048)
    print("alg:", key_algorithm(k))
    print("thumbprint:", jwk_thumbprint(jwk_from_key(k)))
    der = make_csr(k, ["*.example.com", "example.com"])
    req = x509.load_der_x509_csr(der)
    print("csr sane:", req.is_signature_valid, len(der), "bytes")
    e = generate_key("ecc", 256)
    print("ec alg:", key_algorithm(e), "csr ok:",
          x509.load_der_x509_csr(make_csr(e, ["a.example.com"])).is_signature_valid)
