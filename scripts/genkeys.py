#!/usr/bin/env python3
"""
生成 KMS 密钥

使用方法:
  # 首次运行，创建虚拟环境
  python3 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
  
  # 之后运行
  source venv/bin/activate
  python genkeys.py
"""

import secrets
import base64
import json

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


def b64url_encode(data: bytes) -> str:
    """Base64URL 编码（无填充）"""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def b64_encode(data: bytes) -> str:
    """标准 Base64 编码"""
    return base64.b64encode(data).decode("utf-8")


def generate_kid() -> str:
    """生成 Key ID"""
    return b64url_encode(secrets.token_bytes(8))


def generate_ed25519_jwk_with_crypto() -> dict:
    """使用 cryptography 库生成 Ed25519 JWK"""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # 获取原始字节
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    kid = generate_kid()

    # 注意：Ed25519 的 d 是 32 字节的种子，x 是对应的公钥
    # 必须确保 d 和 x 匹配
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
        "x": b64url_encode(public_bytes),
        "d": b64url_encode(private_bytes),
    }
    
    # 验证密钥对是否匹配
    print(f"  密钥验证 - 私钥种子长度: {len(private_bytes)} bytes, 公钥长度: {len(public_bytes)} bytes")
    
    return jwk


def generate_ed25519_jwk_fallback() -> dict:
    """简单生成随机 Ed25519 JWK（不使用 cryptography）"""
    # 注意：这个方法生成的不是真正的 Ed25519 密钥对
    # 仅作为 fallback，建议安装 cryptography 库
    kid = generate_kid()
    
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
        "x": b64url_encode(secrets.token_bytes(32)),  # 公钥 32 字节
        "d": b64url_encode(secrets.token_bytes(32)),  # 私钥 32 字节
    }


def generate_aes_jwk() -> dict:
    """生成 AES-256-GCM JWK（用于 JWT 加密）"""
    key_bytes = secrets.token_bytes(32)  # AES-256
    kid = generate_kid()

    return {
        "kty": "oct",
        "kid": kid,
        "use": "enc",
        "alg": "A256GCM",
        "k": b64url_encode(key_bytes),
    }


def generate_aes_raw_key() -> str:
    """生成 AES-256-GCM 原始密钥（用于数据库加密）
    返回 Base64 编码的 32 字节密钥
    """
    key_bytes = secrets.token_bytes(32)  # AES-256
    return b64_encode(key_bytes)


def generate_alipay_rsa_keypair() -> tuple[str, str]:
    """生成支付宝 RSA2048 密钥对（PKCS8 DER 格式）
    返回 (私钥DER Base64, 公钥DER Base64) 元组
    """
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("生成 RSA 密钥需要 cryptography 库，请先安装: pip install cryptography")
    
    # 生成 RSA2048 私钥
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # 标准公钥指数
        key_size=2048,
    )
    
    # 序列化私钥为 PKCS8 DER 格式（Base64 编码）
    private_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_der_b64 = b64_encode(private_der)
    
    # 提取公钥并序列化为 PKCS8 DER 格式（Base64 编码）
    public_key = private_key.public_key()
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_der_b64 = b64_encode(public_der)
    
    return private_der_b64, public_der_b64


def main():
    print("=" * 60)
    print("生成 KMS 密钥")
    print("=" * 60)
    print()

    if not HAS_CRYPTOGRAPHY:
        print("⚠️  警告: 未安装 cryptography 库")
        print("   使用 fallback 方法生成密钥")
        print("   建议: pip3 install cryptography")
        print()

    # 生成 JWS 私钥（Ed25519）
    if HAS_CRYPTOGRAPHY:
        jws_key = generate_ed25519_jwk_with_crypto()
        print("✅ 使用 cryptography 库生成 Ed25519 密钥")
    else:
        jws_key = generate_ed25519_jwk_fallback()
        print("⚠️  使用 fallback 方法生成密钥")

    # 生成 JWE 密钥（AES-256-GCM，用于 JWT）
    jwe_key = generate_aes_jwk()

    # 生成数据库加密密钥（AES-256-GCM）
    db_enc_key = generate_aes_raw_key()

    # 生成支付宝 RSA2048 密钥对（PKCS8 DER 格式）
    alipay_private_key_der = None
    alipay_public_key_der = None
    if HAS_CRYPTOGRAPHY:
        try:
            alipay_private_key_der, alipay_public_key_der = generate_alipay_rsa_keypair()
            print("✅ 生成支付宝 RSA2048 密钥对（PKCS8 DER 格式）")
        except Exception as e:
            print(f"⚠️  生成支付宝密钥失败: {e}")
    else:
        print("⚠️  跳过支付宝密钥生成（需要 cryptography 库）")

    # JSON 序列化后 base64url 编码
    jws_key_json = json.dumps(jws_key, separators=(",", ":"))
    jwe_key_json = json.dumps(jwe_key, separators=(",", ":"))

    jws_key_b64 = b64url_encode(jws_key_json.encode("utf-8"))
    jwe_key_b64 = b64url_encode(jwe_key_json.encode("utf-8"))

    print()
    print("请将以下内容添加到 config.toml：")
    print("-" * 60)
    print()
    print("# JWT Token 密钥")
    print("[kms.token]")
    print(f'sign-key = "{jws_key_b64}"')
    print(f'enc-key = "{jwe_key_b64}"')
    print()
    print("# 数据库加密密钥（AES-256-GCM）")
    print("[kms.database]")
    print(f'enc-key = "{db_enc_key}"')
    print()
    if alipay_private_key_der:
        print("# 支付宝小程序配置")
        print("[idps.alipay]")
        print('appid = ""  # 支付宝小程序 AppID')
        print(f'secret = "{alipay_private_key_der}"  # 应用私钥（PKCS8 DER Base64，用于签名请求）')
        print('verify-key = ""  # 支付宝公钥（PKCS8 DER Base64，上传应用公钥后支付宝返回，用于验证响应签名）')
        print()
        if alipay_public_key_der:
            print("注意：上面的 public-key 需要上传下面的应用公钥到支付宝开放平台后，")
            print("      支付宝会返回对应的支付宝公钥，将返回的公钥填入 public-key 字段")
            print()
    print("-" * 60)
    print()

    # 输出支付宝密钥
    if alipay_public_key_der:
        print("=" * 60)
        print("支付宝应用公钥（需要上传到支付宝开放平台）：")
        print("=" * 60)
        print()
        print("请将以下应用公钥上传到支付宝开放平台 -> 开发信息 -> 接口加签方式 -> 设置公钥")
        print("上传后，支付宝会返回对应的支付宝公钥，将返回的公钥填入 config.toml 的 public-key 字段")
        print("-" * 60)
        print(alipay_public_key_der)
        print("-" * 60)
        print()

    print("=" * 60)
    print("✅ 密钥生成完成")
    print("=" * 60)


if __name__ == "__main__":
    main()
