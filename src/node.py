"""
单个节点服务

关键点:
  1. DKG 使用 Feldman VSS (G2 承诺)
  2. 份额 + 全局公钥加密落盘, 重启可恢复
  3. partial_sign 校验 cluster 字段
  4. /dkg/commitments 返回 G2 承诺
  5. 多项式在模块加载时生成一次, DKG 重试时不变
"""

import hashlib
import json
import os
import time
import requests
from flask import Flask, request, jsonify

from src.crypto.threshold import ThresholdPSSignature
from src.crypto.utils import (
    serialize_G1, deserialize_G1,
    serialize_G2, deserialize_G2,
    rand_scalar, hash_to_scalar,
)
from src.crypto.storage import ShareStorage


app = Flask(__name__)

# ==================== 配置 ====================

NODE_ID = int(os.environ.get("NODE_ID", "1"))
CLUSTER_NAME = os.environ.get("CLUSTER_NAME", "user_a")
PEER_NODES = [u for u in os.environ.get("PEER_NODES", "").split(",") if u]
THRESHOLD = int(os.environ.get("THRESHOLD", "2"))
NUM_MESSAGES = int(os.environ.get("NUM_MESSAGES", "2"))
NUM_NODES = int(os.environ.get("NUM_NODES", "3"))
MY_URL = os.environ.get("MY_URL", f"http://{CLUSTER_NAME}_node{NODE_ID}:8000")
SHARE_PATH = os.environ.get("SHARE_PATH", f"/data/{CLUSTER_NAME}_node{NODE_ID}.share")
SHARE_PASSPHRASE = os.environ.get("SHARE_PASSPHRASE", "")
AUTH_TOKEN = os.environ.get("AUTH_TOKEN", "")

# 全局状态
_share = None
_global_pk = None
_node_signing_key = None

# 多项式在模块加载时生成一次 (进程生命周期内不变)
_threshold = ThresholdPSSignature(NUM_NODES, THRESHOLD, NUM_MESSAGES)
_my_poly_x = _threshold.generate_polynomial()
_my_poly_y = [_threshold.generate_polynomial() for _ in range(NUM_MESSAGES)]
_my_commit_x = _threshold.commit_polynomial(_my_poly_x)
_my_commit_y = [_threshold.commit_polynomial(p) for p in _my_poly_y]


# ==================== 鉴权 ====================

def require_token(f):
    """简单请求 Token 校验 (生产应换 mTLS)"""
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        if AUTH_TOKEN:
            token = request.headers.get("X-Auth-Token", "")
            if token != AUTH_TOKEN:
                return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper


# ==================== G2 JSON 序列化 (用于公钥持久化) ====================

def _ser_g2(P) -> dict | None:
    """G2 点 -> JSON 字典 {xa, xb, ya, yb}"""
    from py_ecc.optimized_bls12_381 import normalize, is_inf
    if P is None or is_inf(P):
        return None
    x, y = normalize(P)
    xa, xb = x.coeffs
    ya, yb = y.coeffs
    return {"xa": int(xa), "xb": int(xb), "ya": int(ya), "yb": int(yb)}


def _deser_g2(d: dict):
    """JSON 字典 -> G2 点"""
    from py_ecc.optimized_bls12_381 import FQ2
    if d is None:
        return None
    return (
        FQ2([d["xa"], d["xb"]]),
        FQ2([d["ya"], d["yb"]]),
        FQ2.one(),
    )


def _pk_to_dict(pk) -> dict:
    """VerificationKey -> dict (用于磁盘存储)"""
    return {
        "g_tilde": _ser_g2(pk.g_tilde),
        "X_tilde": _ser_g2(pk.X_tilde),
        "Y_tilde": [_ser_g2(y) for y in pk.Y_tilde],
    }


def _dict_to_pk(d: dict):
    """dict -> VerificationKey"""
    from src.crypto.keys import VerificationKey
    return VerificationKey(
        g_tilde=_deser_g2(d["g_tilde"]),
        X_tilde=_deser_g2(d["X_tilde"]),
        Y_tilde=[_deser_g2(y) for y in d["Y_tilde"]],
    )


# ==================== DKG (Feldman VSS, G2 承诺) ====================

def run_dkg():
    """Feldman VSS 版 DKG (承诺在 G2)"""
    global _share, _global_pk, _node_signing_key

    print(f"[{CLUSTER_NAME}-{NODE_ID}] 开始 DKG (Feldman VSS, G2 承诺)...",
          flush=True)

    # 用模块级的多项式和承诺 (不再重新生成)
    threshold = _threshold
    my_poly_x = _my_poly_x
    my_poly_y = _my_poly_y
    my_commit_x = _my_commit_x
    my_commit_y = _my_commit_y

    # 等待 peer
    print(f"[{CLUSTER_NAME}-{NODE_ID}] 等待 peer 就绪...", flush=True)
    wait_for_peers(PEER_NODES, timeout=60, interval=2)

    # Round 1.5: 收集承诺 + 份额
    all_commit_x = [None] * NUM_NODES
    all_commit_y = [None] * NUM_NODES
    all_share_x = [None] * NUM_NODES
    all_share_y = [None] * NUM_NODES

    # 自己的
    all_commit_x[NODE_ID - 1] = my_commit_x
    all_commit_y[NODE_ID - 1] = my_commit_y
    all_share_x[NODE_ID - 1] = threshold.eval_poly(my_poly_x, NODE_ID)
    all_share_y[NODE_ID - 1] = [
        threshold.eval_poly(p, NODE_ID) for p in my_poly_y
    ]

    # 从 peer 拉取
    for peer_url in PEER_NODES:
        try:
            resp = requests.get(
                f"{peer_url}/dkg/commitments",
                headers={"X-Auth-Token": AUTH_TOKEN},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            peer_id = data["node_id"]

            all_commit_x[peer_id - 1] = [
                deserialize_G2(bytes.fromhex(c)) for c in data["commit_x"]
            ]
            all_commit_y[peer_id - 1] = [
                [deserialize_G2(bytes.fromhex(c)) for c in row]
                for row in data["commit_y"]
            ]

            resp2 = requests.get(
                f"{peer_url}/dkg/share_for/{NODE_ID}",
                headers={"X-Auth-Token": AUTH_TOKEN},
                timeout=10,
            )
            resp2.raise_for_status()
            share_data = resp2.json()
            all_share_x[peer_id - 1] = share_data["x"]
            all_share_y[peer_id - 1] = share_data["y"]

            print(f"[{CLUSTER_NAME}-{NODE_ID}] 已获取节点 {peer_id} 的承诺+份额",
                  flush=True)
        except Exception as e:
            print(f"[{CLUSTER_NAME}-{NODE_ID}] 拉取 {peer_url} 失败: {e}",
                  flush=True)

    if any(c is None for c in all_commit_x) or any(s is None for s in all_share_x):
        print(f"[{CLUSTER_NAME}-{NODE_ID}] DKG 失败: 部分节点无响应",
              flush=True)
        return False

    # Round 2: 验证份额并累加
    try:
        _share = threshold.compute_share_from_received(
            all_share_x, all_share_y,
            all_commit_x, all_commit_y,
            NODE_ID,
        )
    except ValueError as e:
        print(f"[{CLUSTER_NAME}-{NODE_ID}] 份额验证失败: {e}", flush=True)
        return False

    print(f"[{CLUSTER_NAME}-{NODE_ID}] 份额已验证并生成", flush=True)

    # Round 3: 全局公钥 (从 G2 承诺求和)
    _global_pk = threshold.compute_global_public_key_from_commitments(
        all_commit_x, all_commit_y
    )
    print(f"[{CLUSTER_NAME}-{NODE_ID}] 全局公钥已计算", flush=True)

    # Round 4: 加密落盘 (份额 + 公钥)
    if SHARE_PASSPHRASE:
        storage = ShareStorage(SHARE_PATH, SHARE_PASSPHRASE)
        storage.save(
            _share, CLUSTER_NAME, NODE_ID,
            global_pk=_pk_to_dict(_global_pk),
        )
        print(f"[{CLUSTER_NAME}-{NODE_ID}] 份额+公钥已加密落盘", flush=True)

    _node_signing_key = rand_scalar()
    return True


def load_share_from_disk() -> bool:
    """从磁盘恢复份额 + 全局公钥"""
    global _share, _global_pk, _node_signing_key
    if not SHARE_PASSPHRASE:
        return False
    try:
        storage = ShareStorage(SHARE_PATH, SHARE_PASSPHRASE)
        data = storage.load()
        if data is None:
            return False

        _share = {"x": data["x"], "y": data["y"]}

        if data.get("global_pk") is not None:
            _global_pk = _dict_to_pk(data["global_pk"])
            print(f"[{CLUSTER_NAME}-{NODE_ID}] 从磁盘恢复份额+公钥成功",
                  flush=True)
        else:
            print(f"[{CLUSTER_NAME}-{NODE_ID}] 从磁盘恢复份额成功 (无公钥)",
                  flush=True)

        _node_signing_key = rand_scalar()
        return True
    except Exception as e:
        print(f"[{CLUSTER_NAME}-{NODE_ID}] 恢复失败: {e}", flush=True)
        return False


# ==================== HTTP 接口 ====================

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "cluster": CLUSTER_NAME,
        "node_id": NODE_ID,
        "dkg_done": _share is not None,
        "pk_ready": _global_pk is not None,
    })


@app.route("/dkg/commitments", methods=["GET"])
@require_token
def get_commitments():
    """返回本节点的 Feldman G2 承诺 (模块级, 永不变化)"""
    return jsonify({
        "node_id": NODE_ID,
        "commit_x": [serialize_G2(c).hex() for c in _my_commit_x],
        "commit_y": [
            [serialize_G2(c).hex() for c in row] for row in _my_commit_y
        ],
    })


@app.route("/dkg/share_for/<int:target_id>", methods=["GET"])
@require_token
def get_share_for(target_id):
    """返回本节点发给 target_id 的份额 (模块级多项式, 永不变化)"""
    x_share = _threshold.eval_poly(_my_poly_x, target_id)
    y_share = [_threshold.eval_poly(p, target_id) for p in _my_poly_y]

    return jsonify({"x": x_share, "y": y_share})


@app.route("/partial_sign", methods=["POST"])
@require_token
def partial_sign():
    """接收部分签名请求"""
    if _share is None:
        return jsonify({"error": "DKG 未完成"}), 503

    data = request.get_json()

    if data.get("cluster") != CLUSTER_NAME:
        return jsonify({"error": "cluster mismatch"}), 403

    messages = data["messages"]
    h_bytes = bytes.fromhex(data["h"])

    try:
        h_point = deserialize_G1(h_bytes)
    except ValueError as e:
        return jsonify({"error": f"invalid h: {e}"}), 400

    sigma1, sigma2 = ThresholdPSSignature.partial_sign(_share, messages, h_point)

    attestation = hash_to_scalar(
        CLUSTER_NAME.encode(),
        serialize_G1(sigma1),
        serialize_G1(sigma2),
        bytes(str(messages), "utf-8"),
        dst=b"NODE_ATTEST",
    )

    return jsonify({
        "party_id": NODE_ID,
        "sigma1": serialize_G1(sigma1).hex(),
        "sigma2": serialize_G1(sigma2).hex(),
        "attestation": hex(attestation),
    })


@app.route("/public_key", methods=["GET"])
def public_key():
    """返回本集群全局公钥 pk = (g̃, X̃, Ỹ_j)"""
    if _global_pk is None:
        return jsonify({"error": "DKG 未完成"}), 503

    return jsonify({
        "g_tilde": _ser_g2(_global_pk.g_tilde),
        "X_tilde": _ser_g2(_global_pk.X_tilde),
        "Y_tilde": [_ser_g2(y) for y in _global_pk.Y_tilde],
    })


def wait_for_peers(peer_urls, timeout=60, interval=2):
    """等待所有 peer 的 /health 就绪"""
    import time as _time
    start = _time.time()
    pending = set(peer_urls)

    while pending and (_time.time() - start) < timeout:
        ready = set()
        for url in pending:
            try:
                resp = requests.get(f"{url}/health", timeout=2)
                if resp.status_code == 200:
                    ready.add(url)
            except Exception:
                pass
        pending -= ready
        if pending:
            print(f"[{CLUSTER_NAME}-{NODE_ID}] 等待 peer: {pending}",
                  flush=True)
            _time.sleep(interval)

    return len(pending) == 0


# ==================== 启动 ====================

def dkg_worker():
    """后台线程: 执行 DKG"""
    import time as _time
    _time.sleep(3)

    recovered = load_share_from_disk()
    if recovered:
        print(f"[{CLUSTER_NAME}-{NODE_ID}] 从磁盘恢复, 跳过 DKG",
              flush=True)
        return

    for attempt in range(5):
        if run_dkg():
            return
        print(f"[{CLUSTER_NAME}-{NODE_ID}] DKG 重试 {attempt + 1}/5...",
              flush=True)
        _time.sleep(5)
    print(f"[{CLUSTER_NAME}-{NODE_ID}] DKG 最终失败", flush=True)


if __name__ == "__main__":
    import threading

    t = threading.Thread(target=dkg_worker, daemon=True)
    t.start()

    port = int(os.environ.get("PORT", "8000"))
    print(f"[{CLUSTER_NAME}-{NODE_ID}] 监听端口 {port}", flush=True)
    app.run(host="0.0.0.0", port=port)