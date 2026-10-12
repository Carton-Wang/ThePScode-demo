"""
客户端: 演示用户 A 和用户 B 各自独立完成阈值签名
"""

import os
import requests


COORDINATOR = "http://localhost:9000"
AUTH_TOKEN = os.environ.get("AUTH_TOKEN", "")


def _headers():
    return {"X-Auth-Token": AUTH_TOKEN} if AUTH_TOKEN else {}


def sign(cluster: str, messages: list) -> dict:
    """请求协调者完成阈值签名"""
    resp = requests.post(
        f"{COORDINATOR}/sign",
        json={"cluster": cluster, "messages": messages},
        headers=_headers(),
    )
    resp.raise_for_status()
    return resp.json()


def verify(cluster: str, messages: list, signature: dict) -> bool:
    """请求协调者验签"""
    resp = requests.post(
        f"{COORDINATOR}/verify",
        json={"cluster": cluster, "messages": messages, "signature": signature},
        headers=_headers(),
    )
    resp.raise_for_status()
    return resp.json()["valid"]


def main():
    print("=" * 60)
    print("分布式 PS 签名演示")
    print("=" * 60)

    # ==================== 用户 A ====================
    messages_a = [11, 22]
    print(f"\n[User A] 集群 3 节点, 阈值 2")
    print(f"  对消息 {messages_a} 签名")

    sig_a = sign("user_a", messages_a)
    print(f"  签名: sigma1={sig_a['sigma1'][:32]}...")
    print(f"  参与节点: {[a['party_id'] for a in sig_a.get('attestations', [])]}")

    valid = verify("user_a", messages_a, sig_a)
    print(f"  验证: {'✓ 通过' if valid else '✗ 失败'}")

    # 篡改消息
    tampered = [11, 999]
    valid_fake = verify("user_a", tampered, sig_a)
    print(f"  篡改消息验证: {'✗ 错误通过' if valid_fake else '✓ 被拒绝'}")

    # ==================== 用户 B ====================
    messages_b = [33, 44]
    print(f"\n[User B] 集群 3 节点, 阈值 2")
    print(f"  对消息 {messages_b} 签名")

    sig_b = sign("user_b", messages_b)
    print(f"  签名: sigma1={sig_b['sigma1'][:32]}...")

    valid_b = verify("user_b", messages_b, sig_b)
    print(f"  验证: {'✓ 通过' if valid_b else '✗ 失败'}")

    # 交叉验证
    valid_cross = verify("user_b", messages_a, sig_a)
    print(f"  用户 A 签名用 B 公钥验证: "
          f"{'✗ 错误通过' if valid_cross else '✓ 被拒绝 (正确)'}")

    # ==================== 未知集群测试 ====================
    print(f"\n[安全测试] 尝试使用未知集群:")
    try:
        sign("user_c", [1, 2])
        print("  ✗ 错误: 未知集群竟然被接受")
    except requests.HTTPError as e:
        print(f"  ✓ 被拒绝 (HTTP {e.response.status_code})")

    print("\n" + "=" * 60)
    print("演示完成")
    print("=" * 60)


if __name__ == "__main__":
    main()