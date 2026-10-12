"""
公私密钥数据结构

对应论文 Section 4.1/4.2:
- 私钥 sk = (x, y_1, ..., y_r) ∈ Z_p^{r+1}
- 公钥 pk = (g̃, X̃, Ỹ_1, ..., Ỹ_r)
"""

from dataclasses import dataclass
from typing import List


@dataclass
class SigningKey:
    """签名私钥 sk = (x, y_1, ..., y_r)"""
    x: int
    y: List[int]          # y_j, j = 1..r，r个消息对应Z_p里的r个私钥元素

    def __post_init__(self):
        assert len(self.y) > 0, "y 列表不能为空"

    @property
    def r(self) -> int:
        return len(self.y) #返回私钥里面y的长度==消息r的数量


@dataclass
class VerificationKey:
    """验证公钥 pk = (g̃, X̃, Ỹ_1, ..., Ỹ_r)"""
    g_tilde: tuple        # g̃
    X_tilde: tuple        # X̃ = g̃^x
    Y_tilde: List[tuple]  # Ỹ_j = g̃^{y_j}

    @property
    def r(self) -> int:
        return len(self.Y_tilde)  #返回公钥里面Y_tilde的数量==消息r的数量