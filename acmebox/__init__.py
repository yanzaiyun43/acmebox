"""acmebox —— ACME（RFC 8555）证书申请工具。

``acmebox.app`` 起一个 HTTP 服务（默认 http://127.0.0.1:8787/），``acmebox.acme``
是协议核心：只依赖标准库与 ``cryptography``，私钥不写入磁盘。
"""

from . import acme as _acme
from .acme import (  # noqa: F401
    AcmeClient,
    AcmeError,
    KNOWN_DIRECTORIES,
    authz_display_name,
    describe_certificate,
    dns01_plans,
    dns01_record_name,
    dns01_value,
    generate_key,
    http01_content,
    jwk_from_key,
    jwk_thumbprint,
    key_algorithm,
    make_csr,
    normalize_domains,
    split_chain,
)

__version__ = _acme.VERSION
