#!/usr/bin/env python3
"""
生成 JWK 密钥
运行: python scripts/genkeys.py
"""

import secrets
import base64
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def b64url_encode(data: bytes) -> str:
    """Base64URL 编码"""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def generate_kid() -> str:
    """生成 Key ID"""
    return b64url_encode(secrets.token_bytes(8))


def generate_ed25519_jwk() -> dict:
    """生成 Ed25519 JWK"""
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

    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
        "x": b64url_encode(public_bytes),
        "d": b64url_encode(private_bytes),
    }


def generate_aes_jwk() -> dict:
    """生成 AES-256-GCM JWK"""
    key_bytes = secrets.token_bytes(32)  # AES-256
    kid = generate_kid()

    return {
        "kty": "oct",
        "kid": kid,
        "use": "enc",
        "alg": "A256GCM",
        "k": b64url_encode(key_bytes),
    }


def main():
    print("=" * 60)
    print("生成 JWK 密钥")
    print("=" * 60)
    print()

    # 生成 JWS 私钥（Ed25519）
    jws_key = generate_ed25519_jwk()

    # 生成 JWE 密钥（AES-256-GCM）
    jwe_key = generate_aes_jwk()

    # JSON 序列化后 base64url 编码
    jws_key_json = json.dumps(jws_key, separators=(",", ":"))
    jwe_key_json = json.dumps(jwe_key, separators=(",", ":"))

    jws_key_b64 = b64url_encode(jws_key_json.encode("utf-8"))
    jwe_key_b64 = b64url_encode(jwe_key_json.encode("utf-8"))

    print("请将以下内容添加到 .env 文件：")
    print("-" * 60)
    print()
    print(f"SIGN_KEY={jws_key_b64}")
    print()
    print(f"ENC_KEY={jwe_key_b64}")
    print()
    print("-" * 60)
    print()

    # 提取公钥
    public_jwk = {
        "kty": jws_key["kty"],
        "crv": jws_key["crv"],
        "kid": jws_key["kid"],
        "use": jws_key["use"],
        "alg": jws_key["alg"],
        "x": jws_key["x"],
    }

    public_jwk_json = json.dumps(public_jwk, indent=2)
    print("签名公钥（JWKS 端点返回，可公开）：")
    print(public_jwk_json)
    print()

    print("=" * 60)
    print("✅ 密钥生成完成")
    print("=" * 60)


if __name__ == "__main__":
    main()

