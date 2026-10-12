"""
PS 签名核心算法

对应论文 Section 4.1/4.2:
签名- Sign(sk, m) -> (σ_1, σ_2)
验证- Verify(pk, m, σ) -> {0,1}
随机化- Randomize(σ) -> σ' 

公共参数生成，公私钥生成，签名生成，验签
关键修正:
  pairing 返回的 FQ12 是 Miller loop 中间结果, 未做 final exponentiation,
  同一个配对值可能有多种 (非规范化) 表示, 直接 == 比较会失败。
  必须先做 final_exponentiate 再比较。
"""

from dataclasses import dataclass
from typing import List, Tuple

from py_ecc.optimized_bls12_381 import (
    Z1, add, multiply, pairing, curve_order,
    final_exponentiate,
)

from .params import PublicParameters
from .keys import SigningKey, VerificationKey
from .utils import rand_scalar, is_identity_G1


@dataclass
class Signature:
    """PS 签名 σ = (σ_1, σ_2) ∈ G1 × G1"""
    sigma1: tuple     # σ_1 = h   
    sigma2: tuple     # σ_2 = h^{x + Σ y_j·m_j}

    def is_well_formed(self) -> bool:
        return not is_identity_G1(self.sigma1) 


class PSSignature:
    """PS 多消息签名方案"""

    def __init__(self, r: int):
        self.pp = PublicParameters.setup(r)
        self.r = r

    def keygen(self) -> Tuple[SigningKey, VerificationKey]:
        """Keygen(pp) -> (sk, pk) 生成公私钥"""
        x = rand_scalar()
        y = [rand_scalar() for _ in range(self.r)]

        X_tilde = multiply(self.pp.g_tilde, x)       #公钥（X_tilde，Y_tilde）
        Y_tilde = [multiply(self.pp.g_tilde, yj) for yj in y]

        sk = SigningKey(x=x, y=y)
        pk = VerificationKey(g_tilde=self.pp.g_tilde,
                             X_tilde=X_tilde, Y_tilde=Y_tilde)
        return sk, pk

    def sign(self, sk: SigningKey, messages: List[int]) -> Signature:
        """Sign(sk, (m_1, ..., m_r)) -> σ   用私钥生成签名，取随机数h，再运算"""
        assert len(messages) == self.r, f"需要 {self.r} 条消息"

        h = multiply(self.pp.g, rand_scalar())

        exponent = sk.x
        for yj, mj in zip(sk.y, messages):
            exponent = (exponent + yj * (mj % curve_order)) % curve_order

        return Signature(sigma1=h, sigma2=multiply(h, exponent))

    def verify(self, pk: VerificationKey, messages: List[int],
               sig: Signature) -> bool:
        """
        Verify(pk, m, σ) -> {0,1}

        验证等式:
          e(σ_1, X̃ · ∏ Ỹ_j^{m_j}) == e(σ_2, g̃)
        """
        if not sig.is_well_formed():
            return False

        # X̃ · ∏ Ỹ_j^{m_j}  ∈ G2
        Y_prod = pk.X_tilde
        for Y_tilde_j, m_j in zip(pk.Y_tilde, messages):
            Y_prod = add(Y_prod, multiply(Y_tilde_j, m_j % curve_order))

        # 左: e(σ_1, X̃·∏Ỹ^m)    右: e(σ_2, g̃)
        # pairing(G2, G1) 参数顺序: 第一参 G2, 第二参 G1
        left = pairing(Y_prod, sig.sigma1)
        right = pairing(pk.g_tilde, sig.sigma2)

        left_norm = final_exponentiate(left)
        right_norm = final_exponentiate(right)

        return left_norm == right_norm

    def randomize(self, sig: Signature) -> Signature:
        """Randomize(σ) -> σ'  取随机数t进行随机化签名"""
        t = rand_scalar()
        return Signature(
            sigma1=multiply(sig.sigma1, t),
            sigma2=multiply(sig.sigma2, t),
        )