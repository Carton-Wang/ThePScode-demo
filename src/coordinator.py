"""
协调者服务

修正点:
  1. 集群白名单校验, 拒绝未知 cluster
  2. 节点 URL 由服务端配置决定, 不接受客户端传入
  3. 收集节点 attestation, 一并返回给客户端
  4. 阈值配置安全失败 (无配置则拒绝签名)
  5. parse_clusters 只按第一个 ":" 分割集群名和节点列表
"""

import os
import secrets as _secrets
import requests
from flask import Flask, request, jsonify

from src.crypto.threshold import ThresholdPSSignature
from src.crypto.core import PSSignature, Signature
from src.crypto.keys import VerificationKey
from src.crypto.utils import (
    serialize_G1, deserialize_G1, hash_to_G1,
)
from py_ecc.optimized_bls12_381 import FQ2


app = Flask(__name__)

CLUSTERS = {}
THRESHOLDS = {}
AUTH_TOKEN = os.environ.get("AUTH_TOKEN", "")


def parse_clusters():
    """
    解析集群配置 (服务端权威配置)

    格式: "cluster1:host1:port1,host2:port2,...;cluster2:..."
    实现要点: 按第一个 ":" 分割集群名和节点列表 (maxsplit=1)
    """
    raw = os.environ.get("CLUSTERS", "")
    for cluster_def in raw.split(";"):
        cluster_def = cluster_def.strip()
        if not cluster_def:
            continue

        if ":" not in cluster_def:
            print(f"[coordinator] 跳过无效集群定义: {cluster_def}",
                  flush=True)
            continue
        cluster_name, nodes_str = cluster_def.split(":", 1)

        nodes = [n.strip() for n in nodes_str.split(",") if n.strip()]
        CLUSTERS[cluster_name] = nodes

        # 读阈值 (安全失败: 无配置则视为不安全)
        th = os.environ.get(f"THRESHOLD_{cluster_name.upper()}")
        if th is not None:
            THRESHOLDS[cluster_name] = int(th)


def require_token(f):
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        if AUTH_TOKEN:
            token = request.headers.get("X-Auth-Token", "")
            if token != AUTH_TOKEN:
                return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper


def deserialize_g2_point(d: dict) -> tuple:
    """JSON 字典 {xa, xb, ya, yb} -> G2 点"""
    return (
        FQ2([d["xa"], d["xb"]]),
        FQ2([d["ya"], d["yb"]]),
        FQ2.one(),
    )


def fetch_public_key(cluster: str) -> VerificationKey:
    """从集群的第一个节点拉取全局公钥 pk = (g̃, X̃, Ỹ_j)"""
    node = CLUSTERS[cluster][0]
    resp = requests.get(
        f"http://{node}/public_key",
        headers={"X-Auth-Token": AUTH_TOKEN},
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()

    return VerificationKey(
        g_tilde=deserialize_g2_point(data["g_tilde"]),
        X_tilde=deserialize_g2_point(data["X_tilde"]),
        Y_tilde=[deserialize_g2_point(y) for y in data["Y_tilde"]],
    )


@app.route("/sign", methods=["POST"])
@require_token
def sign():
    """
    客户端请求签名

    输入:
      { "cluster": "user_a", "messages": [11, 22] }
    """
    data = request.get_json()
    cluster = data.get("cluster")
    messages = data.get("messages")

    if cluster not in CLUSTERS:
        return jsonify({"error": "unknown cluster"}), 403

    if cluster not in THRESHOLDS:
        return jsonify({"error": "cluster threshold not configured"}), 500
    threshold = THRESHOLDS[cluster]

    nodes = CLUSTERS[cluster]

    # 生成共享随机 h (对应论文 h ← G1*)
    h = hash_to_G1(b"coordinator_" + _secrets.token_bytes(32))
    h_hex = serialize_G1(h).hex()

    partial_sigs = []
    attestations = []
    for node_name in nodes:
        try:
            url = f"http://{node_name}/partial_sign"
            resp = requests.post(url, json={
                "cluster": cluster,
                "messages": messages,
                "h": h_hex,
            }, headers={"X-Auth-Token": AUTH_TOKEN}, timeout=15)
            resp.raise_for_status()
            result = resp.json()

            partial_sigs.append((
                result["party_id"],
                deserialize_G1(bytes.fromhex(result["sigma1"])),
                deserialize_G1(bytes.fromhex(result["sigma2"])),
            ))
            attestations.append({
                "party_id": result["party_id"],
                "attestation": result.get("attestation"),
            })
            print(f"[coordinator] 节点 {node_name} 部分签名成功", flush=True)
        except Exception as e:
            print(f"[coordinator] 节点 {node_name} 失败: {e}", flush=True)

    sig = ThresholdPSSignature.aggregate(partial_sigs, threshold)
    if sig is None:
        return jsonify({"error": "聚合失败, 份额不足"}), 400

    return jsonify({
        "sigma1": serialize_G1(sig.sigma1).hex(),
        "sigma2": serialize_G1(sig.sigma2).hex(),
        "attestations": attestations,
    })


@app.route("/verify", methods=["POST"])
@require_token
def verify():
    data = request.get_json()
    cluster = data.get("cluster")

    if cluster not in CLUSTERS:
        return jsonify({"error": "unknown cluster"}), 403

    messages = data["messages"]
    sig_data = data["signature"]

    pk = fetch_public_key(cluster)

    sig = Signature(
        sigma1=deserialize_G1(bytes.fromhex(sig_data["sigma1"])),
        sigma2=deserialize_G1(bytes.fromhex(sig_data["sigma2"])),
    )

    ps = PSSignature(r=pk.r)
    valid = ps.verify(pk, messages, sig)

    return jsonify({"valid": valid})


if __name__ == "__main__":
    parse_clusters()
    print(f"[coordinator] 已加载集群: {list(CLUSTERS.keys())}", flush=True)
    print(f"[coordinator] 集群详情: {CLUSTERS}", flush=True)
    print(f"[coordinator] 已加载阈值: {THRESHOLDS}", flush=True)
    app.run(host="0.0.0.0", port=8000)