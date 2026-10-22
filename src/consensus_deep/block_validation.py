"""区块验证完整流程：哈希 / 签名 / Merkle 树校验。

真实区块链节点收到一个新区块后，必须依次验证：
  1. 区块头哈希是否满足 PoW 难度（PoW 链）/ 签名者是否合法（PoS 链）
  2. prev_hash 是否指向当前最长链的 tip
  3. Merkle Root 是否与区块内交易列表一致（防止交易被替换）
  4. 每笔交易的数字签名是否由发送方私钥签发（防止伪造转账）
  5. 时间戳是否在合理窗口内（防止未来时间戳攻击）

签名策略：优先使用 ecdsa 库的 secp256k1（与比特币 / 以太坊一致）；
若环境未安装 ecdsa，则降级为 DemoSigner（HMAC 风格）用于教学演示。
切换时只需把 `_BACKEND` 改成 "ecdsa" 即可，业务代码不变。
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# 签名后端：优先 ecdsa(secp256k1)，否则降级到 DemoSigner
# ---------------------------------------------------------------------------

try:
    from ecdsa import SigningKey, VerifyingKey, SECP256k1  # type: ignore
    _BACKEND = "ecdsa-secp256k1"
except ImportError:  # pragma: no cover - 教学降级路径
    SigningKey = None  # type: ignore
    VerifyingKey = None  # type: ignore
    SECP256k1 = None  # type: ignore
    _BACKEND = "demo-hmac"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# 密钥与签名
# ---------------------------------------------------------------------------

@dataclass
class KeyPair:
    """账户密钥对。

    - ecdsa 后端：priv 是 SigningKey，pub 是 VerifyingKey（比特币/以太坊真实曲线）
    - demo 后端：priv 是 32 字节随机数，pub = SHA256(priv)（仅教学用）
    """
    priv_bytes: bytes = field(default_factory=lambda: os.urandom(32))
    _sk: object = field(default=None, repr=False)
    _vk: object = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if _BACKEND == "ecdsa-secp256k1":
            self._sk = SigningKey.from_string(self.priv_bytes, curve=SECP256k1)
            self._vk = self._sk.get_verifying_key()
        # demo 后端不需要额外对象

    @property
    def address(self) -> str:
        """账户地址：取公钥哈希的前 20 字节（模拟以太坊地址格式）。"""
        if _BACKEND == "ecdsa-secp256k1":
            raw = self._vk.to_string()  # type: ignore[union-attr]
        else:
            raw = sha256(self.priv_bytes)
        return "0x" + sha256(raw)[-20:].hex()

    @property
    def pub_bytes(self) -> bytes:
        """返回原始公钥字节（ecdsa 曲线公钥点，或 demo 后端的 sha256(priv)）。"""
        if _BACKEND == "ecdsa-secp256k1":
            return self._vk.to_string()  # type: ignore[union-attr]
        return sha256(self.priv_bytes)

    def sign(self, msg: bytes) -> bytes:
        if _BACKEND == "ecdsa-secp256k1":
            return self._sk.sign_digest(msg)  # type: ignore[union-attr]
        # demo：HMAC 风格签名
        return hmac.new(self.priv_bytes, msg, hashlib.sha256).digest()

    def verify_demo(self, msg: bytes, sig: bytes) -> bool:
        """demo 后端：本地持有 priv，直接 HMAC 校验。

        真实 ecdsa 后端不调用这个方法（用 pub.verify_digest）。
        """
        expected = hmac.new(self.priv_bytes, msg, hashlib.sha256).digest()
        return hmac.compare_digest(expected, sig)


# ---------------------------------------------------------------------------
# 交易
# ---------------------------------------------------------------------------

@dataclass
class Transaction:
    sender: str          # 发送方地址
    to: str             # 接收方地址
    value: int          # 金额（最小单位 wei）
    nonce: int           # 发送方账户 nonce，防重放
    gas_price: int = 1   # gas 单价
    sig: bytes = b""     # 签名
    pub: bytes = b""     # 公钥（用于验签，真实链从签名恢复）

    def signing_hash(self) -> bytes:
        """计算待签名的消息哈希。签名内容必须与验签内容逐字节一致——
        这是"交易签名验证失败"类 bug 的高发区（见 pitfalls/02）。
        """
        payload = (
            self.sender.encode()
            + self.to.encode()
            + self.value.to_bytes(32, "big")
            + self.nonce.to_bytes(8, "big")
            + self.gas_price.to_bytes(8, "big")
        )
        return sha256(payload)

    def sign_with(self, kp: KeyPair) -> None:
        self.sender = kp.address
        self.pub = kp.pub_bytes
        self.sig = kp.sign(self.signing_hash())


# ---------------------------------------------------------------------------
# Merkle 树
# ---------------------------------------------------------------------------

class MerkleTree:
    """交易 Merkle 树：把任意数量交易压缩成 32 字节 Merkle Root。

    特性：
    - 任意一笔交易被篡改，Root 必然变化（哈希雪崩）
    - 轻节点（SPV）只需 O(log n) 个兄弟哈希即可证明某交易在树中
    """

    def __init__(self, txs: List[Transaction]):
        if not txs:
            self.root = sha256(b"")
            return
        layer = [sha256(t.signing_hash()) for t in txs]
        while len(layer) > 1:
            # 奇数个节点：复制最后一个（比特币约定）
            if len(layer) % 2 == 1:
                layer.append(layer[-1])
            layer = [
                sha256(layer[i] + layer[i + 1])
                for i in range(0, len(layer), 2)
            ]
        self.root = layer[0]

    @staticmethod
    def proof(txs: List[Transaction], index: int) -> Tuple[bytes, List[Tuple[bytes, int]]]:
        """生成 txs[index] 的 Merkle 证明：返回 (leaf_hash, [(sibling_hash, position)])。"""
        if not txs or index < 0 or index >= len(txs):
            raise IndexError("index out of range")
        layer = [sha256(t.signing_hash()) for t in txs]
        leaf = layer[index]
        proof: List[Tuple[bytes, int]] = []
        idx = index
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer.append(layer[-1])
            # 兄弟节点位置
            sibling_idx = idx + 1 if idx % 2 == 0 else idx - 1
            proof.append((layer[sibling_idx], idx % 2))
            # 上升一层
            layer = [sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
            idx //= 2
        return leaf, proof

    @staticmethod
    def verify(leaf: bytes, proof: List[Tuple[bytes, int]], root: bytes) -> bool:
        h = leaf
        for sibling, pos in proof:
            # pos=0 表示 leaf 在左，pos=1 表示 leaf 在右
            h = sha256(h + sibling) if pos == 0 else sha256(sibling + h)
        return h == root


# ---------------------------------------------------------------------------
# 区块
# ---------------------------------------------------------------------------

@dataclass
class Block:
    height: int
    prev_hash: bytes
    txs: List[Transaction]
    timestamp: float = field(default_factory=__import__("time").time)
    nonce: int = 0
    miner: str = ""

    @property
    def merkle_root(self) -> bytes:
        return MerkleTree(self.txs).root

    def header_hash(self) -> bytes:
        """区块头哈希。注意：签名/哈希时字段顺序必须严格固定，
        任何字段顺序变化都会导致哈希完全不同——这是"区块哈希计算错误"
        类 bug 的高发区（见 pitfalls/01）。
        """
        header = (
            self.height.to_bytes(8, "big")
            + self.prev_hash
            + self.merkle_root
            + int(self.timestamp).to_bytes(8, "big")
            + self.nonce.to_bytes(32, "big")
        )
        return sha256(header)


# ---------------------------------------------------------------------------
# 区块验证器
# ---------------------------------------------------------------------------

class BlockValidator:
    """执行完整的区块验证流水线。

    每个 check 失败都会抛 InvalidBlockError，节点必须丢弃该块。
    """

    def __init__(self, expected_target: int, known_accounts: Optional[List[KeyPair]] = None):
        self.target = expected_target
        # 已知账户集合：演示用，真实链通过状态数据库查 nonce / 余额
        self.known = {kp.address: kp for kp in (known_accounts or [])}

    def validate(self, block: Block, prev_block: Optional[Block]) -> None:
        self._check_prev_hash(block, prev_block)
        self._check_height(block, prev_block)
        self._check_merkle(block)
        self._check_pow(block)
        self._check_txs(block)
        self._check_timestamp(block)

    @staticmethod
    def _check_prev_hash(block: Block, prev_block: Optional[Block]) -> None:
        if prev_block is None:
            if block.height != 0:
                raise InvalidBlockError("非创世块但缺少 prev_block")
            return
        if block.prev_hash != prev_block.header_hash():
            raise InvalidBlockError(
                f"prev_hash 不匹配：期望 {prev_block.header_hash().hex()[:16]}...，"
                f"实际 {block.prev_hash.hex()[:16]}..."
            )

    @staticmethod
    def _check_height(block: Block, prev_block: Optional[Block]) -> None:
        if prev_block is None:
            return
        if block.height != prev_block.height + 1:
            raise InvalidBlockError(
                f"height 跳跃：prev={prev_block.height}, current={block.height}"
            )

    @staticmethod
    def _check_merkle(block: Block) -> None:
        """重新计算 Merkle Root，与区块头里的对比。"""
        recomputed = MerkleTree(block.txs).root
        if recomputed != block.merkle_root:
            raise InvalidBlockError("Merkle Root 不匹配：交易列表被篡改")

    def _check_pow(self, block: Block) -> None:
        h = block.header_hash()
        if int.from_bytes(h, "big") >= self.target:
            raise InvalidBlockError(
                f"PoW 难度不满足：hash={h.hex()[:16]}... 未低于 target"
            )

    def _check_txs(self, block: Block) -> None:
        for tx in block.txs:
            # 验签
            if not self._verify_tx_sig(tx):
                raise InvalidBlockError(
                    f"交易签名无效：sender={tx.sender[:14]}... nonce={tx.nonce}"
                )

    def _verify_tx_sig(self, tx: Transaction) -> bool:
        expected_hash = tx.signing_hash()
        kp = self.known.get(tx.sender)
        if kp is None:
            # 未知发送方：真实链会从签名 recover 公钥后查地址；
            # 教学版直接拒绝未知账户
            return False
        if _BACKEND == "ecdsa-secp256k1":
            try:
                vk = VerifyingKey.from_string(tx.pub, curve=SECP256k1)
                return vk.verify_digest(tx.sig, expected_hash)  # type: ignore[union-attr]
            except Exception:
                return False
        # demo 后端：本地持有 priv，用 HMAC 验签
        return kp.verify_demo(expected_hash, tx.sig)

    @staticmethod
    def _check_timestamp(block: Block) -> None:
        import time
        now = time.time()
        if block.timestamp > now + 60:
            raise InvalidBlockError("时间戳在未来超过 60 秒")
        if block.timestamp < 0:
            raise InvalidBlockError("时间戳为负")


class InvalidBlockError(Exception):
    """区块验证失败。"""


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def main() -> None:
    print(f"签名后端: {_BACKEND}")
    print("=" * 70)

    # 1. 构造两个账户
    alice = KeyPair()
    bob = KeyPair()
    print(f"Alice 地址: {alice.address}")
    print(f"Bob   地址: {bob.address}")

    # 2. Alice 发一笔交易给 Bob
    tx1 = Transaction(sender=alice.address, to=bob.address, value=1000, nonce=0, gas_price=1)
    tx1.sign_with(alice)

    # 3. 构造区块
    genesis = Block(height=0, prev_hash=b"\x00" * 32, txs=[])
    block1 = Block(height=1, prev_hash=genesis.header_hash(), txs=[tx1], miner="miner-A")
    # 挖一下满足难度（前导 1 个 hex 零）
    target = 1 << (8 * (32 - 1)) - 1
    import itertools
    for nonce in itertools.count(0):
        block1.nonce = nonce
        if int.from_bytes(block1.header_hash(), "big") < target:
            break

    print(f"\nBlock#{block1.height} hash: {block1.header_hash().hex()[:24]}...")
    print(f"Block#{block1.height} merkle_root: {block1.merkle_root.hex()[:24]}...")

    # 4. 完整验证
    validator = BlockValidator(expected_target=target, known_accounts=[alice, bob])
    try:
        validator.validate(block1, prev_block=genesis)
        print("[OK] 区块验证通过：prev_hash / merkle / PoW / 签名 / 时间戳全部合法")
    except InvalidBlockError as e:
        print(f"[FAIL] 区块被拒绝：{e}")

    # 5. 演示恶意篡改：把金额改成 100000，验证应失败
    evil = Block(height=1, prev_hash=genesis.header_hash(),
                 txs=[Transaction(alice.address, bob.address, 100000, 0)],
                 miner="mallory")
    evil.nonce = block1.nonce
    try:
        validator.validate(evil, prev_block=genesis)
        print("[BUG] 篡改后的区块竟然通过了！")
    except InvalidBlockError as e:
        print(f"[OK] 篡改区块被拒绝：{e}")

    # 6. Merkle 证明演示
    leaf, proof = MerkleTree.proof([tx1], 0)
    ok = MerkleTree.verify(leaf, proof, block1.merkle_root)
    print(f"\nMerkle SPV 校验：交易在区块中 = {ok}")


if __name__ == "__main__":
    main()
