"""
份额安全存储

- 份额加密后落盘 (AES-GCM + scrypt)
- 同时持久化全局公钥, 重启后可恢复
"""

import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class ShareStorage:
    """
    份额 + 公钥加密存储

    文件格式:
      {
        "salt": hex,
        "nonce": hex,
        "ciphertext": hex,       # 加密后的 {share, global_pk}
        "cluster": str,
        "node_id": int
      }
    """

    def __init__(self, path: str, passphrase: str):
        self.path = Path(path)
        self.passphrase = passphrase.encode()

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        return kdf.derive(self.passphrase)

    def save(self, share: dict, cluster: str, node_id: int,
             global_pk: dict | None = None) -> None:
        """
        保存份额 (必须) + 全局公钥 (可选, 用于重启恢复)

        global_pk 结构 (与论文符号对齐):
          {
            "g_tilde": {...},   # g̃
            "X_tilde": {...},   # X̃
            "Y_tilde": [{...}, ...]  # Ỹ_j
          }
        """
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive_key(salt)

        payload_dict = {
            "x": share["x"],
            "y": share["y"],
        }
        if global_pk is not None:
            payload_dict["global_pk"] = global_pk

        payload = json.dumps(payload_dict).encode()

        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, payload, None)

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w") as f:
            json.dump({
                "salt": salt.hex(),
                "nonce": nonce.hex(),
                "ciphertext": ct.hex(),
                "cluster": cluster,
                "node_id": node_id,
            }, f)

    def load(self) -> dict | None:
        """
        加载份额 (和公钥, 如果存在)

        返回:
          {
            "x": int,
            "y": [int, ...],
            "global_pk": dict 或 None
          }
        """
        if not self.path.exists():
            return None
        with open(self.path) as f:
            data = json.load(f)

        salt = bytes.fromhex(data["salt"])
        nonce = bytes.fromhex(data["nonce"])
        ct = bytes.fromhex(data["ciphertext"])
        key = self._derive_key(salt)

        aesgcm = AESGCM(key)
        try:
            payload = aesgcm.decrypt(nonce, ct, None)
        except Exception:
            raise ValueError("份额解密失败: 口令错误或文件被篡改")

        share = json.loads(payload)
        result = {"x": share["x"], "y": share["y"]}
        if "global_pk" in share:
            result["global_pk"] = share["global_pk"]
        else:
            result["global_pk"] = None
        return result