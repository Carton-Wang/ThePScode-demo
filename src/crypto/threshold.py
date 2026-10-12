"""
阈值 PS 签名 + 分布式密钥生成 (DKG)

对应论文 Section 4.2 的多消息 PS 签名, 但把单机私钥拆成 (t, n) 份额。

关键设计:
  - Feldman VSS 承诺用 G2 生成元 (C_k = g̃^{a_k})
  - 原因: PS 签名的全局公钥 X̃ = g̃^x 在 G2 上,
         Feldman 承诺必须和目标公钥在同一群
  - 份额验证: g̃^{f(i)} == ∏ C_k^{i^k}
  - 全局公钥: X̃ = Σ C_{i,0}, Ỹ_j = Σ C_{i,j,0}

⭐ 阈值语义:
  t 表示最少需要 t 份才能聚合签名, 多项式次数为 t-1
"""

from typing import Dict, List, Optional, Set, Tuple

from py_ecc.optimized_bls12_381 import (
    G1, G2, Z1, Z2, add, multiply, curve_order,
    normalize, is_inf,
)

from .keys import VerificationKey
from .core import Signature


# ==================== 点比较 (归一化) ====================比较两个点是不是同一个点

def _eq_g1(P, Q) -> bool:
    """比较两个 G1 点 (仿射坐标)"""
    if is_inf(P) and is_inf(Q):
        return True
    if is_inf(P) or is_inf(Q):
        return False
    return normalize(P) == normalize(Q)


def _eq_g2(P, Q) -> bool:
    """比较两个 G2 点 (仿射坐标)"""
    if is_inf(P) and is_inf(Q):
        return True
    if is_inf(P) or is_inf(Q):
        return False
    return normalize(P) == normalize(Q)


class ThresholdPSSignature:
    """
    (t, n) 阈值 PS 签名

    参数:
      n: 节点总数
      t: 最少需要 t 份才能签名 (阈值)
      r: 每条签名覆盖的消息数
    """

    def __init__(self, n: int, t: int, r: int):
        assert 0 < t <= n, "阈值必须满足 0 < t <= n"
        assert r > 0, "消息数量必须为正"
        self.n = n
        self.t = t
        self.r = r
        self.g = G1
        self.g_tilde = G2

    # ==================== 多项式运算 ====================
    # 用于计算给节点的份额

    @staticmethod
    def eval_poly(coeffs: List[int], x: int) -> int:
        """f(x) = a_0 + a_1·x + ... + a_d·x^d mod p"""
        result = 0
        x_pow = 1
        for c in coeffs:
            result = (result + c * x_pow) % curve_order
            x_pow = (x_pow * x) % curve_order
        return result

    # ==================== Feldman VSS ====================

    def generate_polynomial(self) -> List[int]:
        """生成 (t-1) 次随机多项式 [a_0, ..., a_{t-1}]"""
        import secrets
        return [secrets.randbelow(curve_order) for _ in range(self.t)]

    def commit_polynomial(self, coeffs: List[int]) -> List[tuple]:
        """Feldman 承诺: C_k = g̃^{a_k} ∈ G2"""
        return [multiply(self.g_tilde, c) for c in coeffs]

    def verify_share_against_commitment(
        self, share_value: int, party_id: int, commitments: List[tuple]
    ) -> bool:
        """验证份额: g̃^{f(party_id)} == ∏_k C_k^{party_id^k}  验证节点收到的份额是否合法"""
        lhs = multiply(self.g_tilde, share_value)

        rhs = Z2
        x_pow = 1
        for C_k in commitments:
            rhs = add(rhs, multiply(C_k, x_pow))
            x_pow = (x_pow * party_id) % curve_order

        return _eq_g2(lhs, rhs)

    def compute_share_from_received(
        self,
        received_x_shares: List[int],
        received_y_shares: List[List[int]],
        commit_x_list: List[List[tuple]],
        commit_y_list: List[List[List[tuple]]],
        party_id: int,
    ) -> Dict:
        """从收到的份额 + 承诺计算单个节点最终份额, 并验证每个来源"""
        assert len(received_x_shares) == self.n
        assert len(received_y_shares) == self.n

        x_share = 0
        y_shares = [0] * self.r

        for i in range(self.n):
            # 验证 x 份额
            if not self.verify_share_against_commitment(
                received_x_shares[i], party_id, commit_x_list[i]
            ):
                raise ValueError(f"节点 {i+1} 的 x 份额验证失败")
            x_share = (x_share + received_x_shares[i]) % curve_order

            # 验证每个 y 份额
            for k in range(self.r):
                if not self.verify_share_against_commitment(
                    received_y_shares[i][k], party_id, commit_y_list[i][k]
                ):
                    raise ValueError(f"节点 {i+1} 的第 {k} 个 y 份额验证失败")
                y_shares[k] = (y_shares[k] + received_y_shares[i][k]) % curve_order

        return {'x': x_share, 'y': y_shares}

    def compute_global_public_key_from_commitments(
        self,
        commit_x_list: List[List[tuple]],
        commit_y_list: List[List[List[tuple]]],
    ) -> VerificationKey:
        """
        从 G2 承诺计算全局公钥:
          X̃ = Σ C_{i,0}
          Ỹ_j = Σ C_{i,j,0}
        """
        X_tilde = Z2
        for commits in commit_x_list:
            X_tilde = add(X_tilde, commits[0])

        Y_tilde = []
        for k in range(self.r):
            Yk = Z2
            for i in range(self.n):
                Yk = add(Yk, commit_y_list[i][k][0])
            Y_tilde.append(Yk)

        return VerificationKey(g_tilde=self.g_tilde,
                               X_tilde=X_tilde, Y_tilde=Y_tilde)

    # ==================== 部分签名 ====================

    @staticmethod
    def partial_sign(share: Dict, messages: List[int], h: tuple
                     ) -> Tuple[tuple, tuple]:
        """节点用自己的份额生成部分签名: σ_2 = h^{x_i + Σ y_{i,j}·m_j}"""
        exponent = share['x'] #自己的部分私钥
        for y_share, m in zip(share['y'], messages):
            exponent = (exponent + y_share * (m % curve_order)) % curve_order
        return h, multiply(h, exponent)

    # ==================== Lagrange ====================

    @staticmethod
    def lagrange_coefficient(i: int, indices: Set[int]) -> int:
        """计算 Lagrange 系数 λ_i  后续要用他来聚合计算"""
        num, den = 1, 1
        for j in indices:
            if i == j:
                continue
            num = (num * (curve_order - j)) % curve_order
            den = (den * (i - j)) % curve_order
        return (num * pow(den, curve_order - 2, curve_order)) % curve_order

    # ==================== 聚合 ====================

    @staticmethod
    def aggregate(
        partial_sigs: List[Tuple[int, tuple, tuple]],
        threshold: int,
    ) -> Optional[Signature]:
        """
        聚合 t 个部分签名为最终签名

        参数:
          partial_sigs: [(party_id, σ_1, σ_2), ...]
          threshold:    最少份数 t
        """
        if len(partial_sigs) < threshold:
            return None

        indices = {pid for pid, _, _ in partial_sigs}
        sigma1 = partial_sigs[0][1]

        sigma2 = Z1
        for pid, s1_i, s2_i in partial_sigs:
            # σ_1 必须所有节点相同 (归一化后比较)
            if not _eq_g1(s1_i, sigma1):
                return None
            lam = ThresholdPSSignature.lagrange_coefficient(pid, indices)
            sigma2 = add(sigma2, multiply(s2_i, lam))

        return Signature(sigma1=sigma1, sigma2=sigma2)