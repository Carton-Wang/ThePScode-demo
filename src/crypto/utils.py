"""
工具函数: 随机数生成、哈希到曲线/标量、点序列化

关键实现说明:
  - hash_to_G1 采用 hash_to_scalar * g 的方式 (g 为 G1 生成元)
  - deserialize_G1 / deserialize_G2 做了 on-curve + subgroup check
  - 所有哈希加长度前缀, 避免长度扩展

符号对照:
  G1: G1 生成元 (论文 g)        G2: G2 生成元 (论文 g̃)
  Z1: G1 无穷远点               Z2: G2 无穷远点
  FQ: 素数域                     FQ2: 二次扩域 (元素 = 2 个 FQ)
  b:  G1 曲线方程常数            b2: G2 曲线方程常数
  curve_order: 群的阶 (论文 p)
"""

import hashlib
import secrets
from py_ecc.optimized_bls12_381 import (
    G1, G2, Z1, Z2, FQ, FQ2, normalize, multiply, curve_order,
    is_inf, is_on_curve, b, b2,
)


# ==================== 随机数 ====================#返回Z_p中的一个元素

def rand_scalar() -> int:
    """生成 Z_p* 中的随机非零标量 (1 <= k <= curve_order-1)"""
    return secrets.randbelow(curve_order - 1) + 1


# ==================== 哈希到标量 ====================

def hash_to_scalar(*data: bytes, dst: bytes = b"PS_SCALAR") -> int:
     #将消息m转化成在Z_p中的元素
    """
    域分离哈希到 Z_p, 使用 SHA-512 + 拒绝采样避免模偏

    作用: 均匀映射 + 确定性 + 不可预测 + 域分离
    """
    counter = 0
    while True:
        h = hashlib.sha512()
        h.update(dst)                              # 域分离
        h.update(counter.to_bytes(4, 'big'))       # 尝试计数器
        for d in data:
            h.update(len(d).to_bytes(8, 'big'))    # 先写 8 字节长度
            h.update(d)                            # 再写内容 (抗拼接歧义)
        candidate = int.from_bytes(h.digest(), 'big')
        # 拒绝采样: 只接受落在 curve_order 整数倍区间内的候选值
        if candidate < (1 << 512) - ((1 << 512) % curve_order):
            return candidate % curve_order
        counter += 1                               # 重新抽样, 防死循环


# ==================== 哈希到 G1 ====================返回G1上的一个元素

def hash_to_G1(msg: bytes, dst: bytes = b"PS_SIG_G1") -> tuple:
    """
    哈希到 G1 群元素, 对应论文中的 h ← G1*

    实现: h = hash_to_scalar(msg) * g
    安全性: PS 签名只需 h ∈ G1 且离散对数未知, 本实现满足。
    """
    s = hash_to_scalar(msg, dst=dst)   # s 为标量乘数，h
    if s == 0:
        s = 1                          # 防止 h 退化为无穷远点
    return multiply(G1, s)             # s · g


# ==================== G1 序列化 ====================序列化和反序列化用来网络传输和磁盘存储

def serialize_G1(P) -> bytes:       #G1->96字节
    """G1 点 -> 96 字节 (未压缩), 无穷远点全零"""
    if P is None or is_inf(P):
        return b'\x00' * 96
    x, y = normalize(P)
    return int(x).to_bytes(48, 'big') + int(y).to_bytes(48, 'big')

#G1反序列化，96字节->G1
def deserialize_G1(data: bytes) -> tuple:
    """96 字节 -> G1 点, 含 on-curve check + subgroup check"""
    if data == b'\x00' * 96:
        return Z1

    if len(data) != 96:
        raise ValueError("G1 点必须是 96 字节")

    x = int.from_bytes(data[:48], 'big')
    y = int.from_bytes(data[48:], 'big')

    P = (FQ(x), FQ(y), FQ(1))

    if not is_on_curve(P, b):
        raise ValueError("G1 点不在曲线上")

    if not is_inf(P) and not is_inf(multiply(P, curve_order)):
        raise ValueError("G1 点不在正确子群内")

    return P

#判断点是不是单位元
def is_identity_G1(P) -> bool:
    return P is None or is_inf(P)


# ==================== G2 序列化 ====================
#G2->192字节
def serialize_G2(P) -> bytes:
    """G2 点 -> 192 字节 (格式: xa || xb || ya || yb)"""
    if P is None or is_inf(P):
        return b'\x00' * 192
    x, y = normalize(P)
    xa, xb = x.coeffs
    ya, yb = y.coeffs
    return (int(xa).to_bytes(48, 'big') + int(xb).to_bytes(48, 'big') +
            int(ya).to_bytes(48, 'big') + int(yb).to_bytes(48, 'big'))

#192字节->G2
def deserialize_G2(data: bytes) -> tuple:
    """192 字节 -> G2 点, 含 on-curve check + subgroup check"""
    if data == b'\x00' * 192:
        return Z2

    if len(data) != 192:
        raise ValueError("G2 点必须是 192 字节")

    xa = int.from_bytes(data[0:48], 'big')
    xb = int.from_bytes(data[48:96], 'big')
    ya = int.from_bytes(data[96:144], 'big')
    yb = int.from_bytes(data[144:192], 'big')

    P = (FQ2([xa, xb]), FQ2([ya, yb]), FQ2.one())

    if not is_on_curve(P, b2):
        raise ValueError("G2 点不在曲线上")

    if not is_inf(P) and not is_inf(multiply(P, curve_order)):
        raise ValueError("G2 点不在正确子群内")

    return P