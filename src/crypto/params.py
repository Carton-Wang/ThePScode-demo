"""
系统公共参数 pp

对应论文 Section 2.1: Bilinear Groups
- Type-3 双线性群 (G1 != G2, 无同态)
- 使用 BLS12-381 曲线
"""

from dataclasses import dataclass
from py_ecc.optimized_bls12_381 import G1, G2


@dataclass(frozen=True)
class PublicParameters:
    """
    Setup(1^k, r) -> pp

    字段:
      g:       G1 群的生成元 (论文中的 g)
      g_tilde: G2 群的生成元 (论文中的 g̃)
      r:       每条签名覆盖的消息数量 r
    """
    g: G1
    g_tilde: G2
    r: int

    @classmethod
    def setup(cls, r: int) -> 'PublicParameters':   
        """标准 Setup 算法"""
        assert r >= 0, "消息数量必须为非负整数"
        return cls(g=G1, g_tilde=G2, r=r)    #输出公参，用来构造对象，创建pp

    def __repr__(self) -> str:
        return f"PublicParameters(r={self.r})"  #控制打印的函数