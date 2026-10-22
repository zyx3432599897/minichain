"""Merkle Patricia Trie（MPT）状态树：状态根哈希 + 增量更新。

以太坊为什么用 MPT？
- 需要一个密码学累加器：任意 key->value 集合压缩成 32 字节 root hash。
- 任意节点篡改都会让 root hash 变化（Merkle 特性）。
- 需要支持增量更新：改一个 key，只重算路径上 O(log n) 个节点的哈希。

MPT 节点类型：
- LeafNode(path, value)：终止节点
- ExtensionNode(prefix, child)：共享前缀压缩
- BranchNode：16 个 nibble 分支 + 1 个终止 value
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hex_to_nibbles(hex_str: str) -> List[int]:
    return [int(c, 16) for c in hex_str]


def nibbles_to_hp(nibbles: List[int], is_leaf: bool) -> bytes:
    odd = len(nibbles) % 2 == 1
    flag = 0x20 if is_leaf else 0x00
    if odd:
        out = [flag + 0x10 + nibbles[0]]
        rest = nibbles[1:]
    else:
        out = [flag]
        rest = nibbles
    for i in range(0, len(rest), 2):
        out.append(rest[i] * 16 + rest[i + 1])
    return bytes(out)


@dataclass
class _Leaf:
    path: List[int]
    value: bytes
    def hash(self) -> bytes:
        payload = b"leaf|" + nibbles_to_hp(self.path, is_leaf=True) + b"|" + self.value
        return sha256(payload)


@dataclass
class _Extension:
    prefix: List[int]
    child: object
    def hash(self) -> bytes:
        payload = b"ext|" + nibbles_to_hp(self.prefix, is_leaf=False) + b"|" + self.child.hash()
        return sha256(payload)


@dataclass
class _Branch:
    branches: List[Optional[object]]
    value: Optional[bytes] = None
    def hash(self) -> bytes:
        h = b"branch|"
        for b in self.branches:
            h += (b.hash() if b else b"\x00" * 32)
        h += (self.value or b"")
        return sha256(h)


class MerklePatriciaTrie:
    def __init__(self, root: Optional[object] = None):
        self._root = root

    def get(self, key_hex: str) -> Optional[bytes]:
        if self._root is None:
            return None
        return self._get(self._root, hex_to_nibbles(key_hex))

    def _get(self, node: object, path: List[int]) -> Optional[bytes]:
        if isinstance(node, _Leaf):
            return node.value if node.path == path else None
        if isinstance(node, _Extension):
            plen = len(node.prefix)
            if path[:plen] == node.prefix:
                return self._get(node.child, path[plen:])
            return None
        if isinstance(node, _Branch):
            if not path:
                return node.value
            nxt = node.branches[path[0]]
            return self._get(nxt, path[1:]) if nxt else None
        return None

    def update(self, key_hex: str, value: bytes) -> "MerklePatriciaTrie":
        nibbles = hex_to_nibbles(key_hex)
        new_root = _Leaf(path=nibbles, value=value) if self._root is None \
            else self._update(self._root, nibbles, value)
        return MerklePatriciaTrie(new_root)

    def _update(self, node: object, path: List[int], value: bytes) -> object:
        if isinstance(node, _Leaf):
            if node.path == path:
                return _Leaf(path=path, value=value)
            common = _common_prefix_len(node.path, path)
            return self._split_leaf(node, path, value, common)
        if isinstance(node, _Extension):
            plen = len(node.prefix)
            common = _common_prefix_len(node.prefix, path)
            if common == plen:
                return _Extension(prefix=node.prefix,
                                  child=self._update(node.child, path[plen:], value))
            uprefix = node.prefix[:common]
            rest_ext = node.prefix[common:]
            rest_new = path[common:]
            branch = _Branch(branches=[None] * 16)
            inner = node.child if len(rest_ext) <= 1 else \
                _Extension(prefix=rest_ext[1:], child=node.child)
            branch.branches[rest_ext[0]] = inner
            if rest_new:
                branch.branches[rest_new[0]] = _Leaf(path=rest_new[1:], value=value) \
                    if len(rest_new) > 1 else _Branch(branches=[None]*16, value=value)
            else:
                branch.value = value
            return _Extension(prefix=uprefix, child=branch)
        if isinstance(node, _Branch):
            if not path:
                return _Branch(branches=list(node.branches), value=value)
            idx = path[0]
            old_child = node.branches[idx]
            new_branches = list(node.branches)
            if old_child is None:
                new_branches[idx] = _Leaf(path=path[1:], value=value)
            else:
                new_branches[idx] = self._update(old_child, path[1:], value)
            return _Branch(branches=new_branches, value=node.value)
        raise TypeError(f"未知节点类型: {type(node)}")

    def _split_leaf(self, old_leaf: _Leaf, new_path: List[int],
                    new_value: bytes, common: int) -> object:
        branch = _Branch(branches=[None] * 16)
        old_rest = old_leaf.path[common:]
        new_rest = new_path[common:]
        if not old_rest:
            branch.value = old_leaf.value
        else:
            branch.branches[old_rest[0]] = _Leaf(path=old_rest[1:], value=old_leaf.value) \
                if len(old_rest) > 1 else _Branch(branches=[None]*16, value=old_leaf.value)
        if not new_rest:
            branch.value = new_value
        else:
            branch.branches[new_rest[0]] = _Leaf(path=new_rest[1:], value=new_value) \
                if len(new_rest) > 1 else _Branch(branches=[None]*16, value=new_value)
        if common == 0:
            return branch
        return _Extension(prefix=old_leaf.path[:common], child=branch)

    @property
    def root_hash(self) -> bytes:
        return self._root.hash() if self._root else b"\x00" * 32

    def root_hash_hex(self) -> str:
        return "0x" + self.root_hash.hex()


def _common_prefix_len(a: List[int], b: List[int]) -> int:
    n = min(len(a), len(b))
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    return i


def main() -> None:
    print("=" * 70)
    print("Merkle Patricia Trie 状态树演示")
    print("=" * 70)
    t = MerklePatriciaTrie()
    print(f"初始 root = {t.root_hash_hex()}")
    kvs = [("a1", b"alice"), ("a1b2", b"bob"), ("a1c3", b"carol"),
           ("b2", b"dave"), ("a1b2d4", b"eve")]
    for k, v in kvs:
        t = t.update(k, v)
        print(f"  update({k:8s}) -> root={t.root_hash_hex()[:20]}...")
    print("\n查询：")
    for k, _ in kvs:
        print(f"  get({k}) = {t.get(k)}")
    print(f"  get(不存在) = {t.get('ff')}")


if __name__ == "__main__":
    main()
