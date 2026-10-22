"""分叉解决：最长链原则（Nakamoto）vs GHOST 协议对比。

为什么会有分叉？
- PoW 网络中，两个矿工几乎同时找到合法 nonce，两个块都会被各自邻居接受，
  链就分裂成两条。后续矿工在不同 tip 上继续挖，分裂持续到其中一条胜出。

两种主流动态选择协议：
1. 最长链原则（比特币 / Nakamoto）：
   选"累积工作量最大"的链（在难度一致时等价于高度最高）。
   缺点：出块越快，临时分叉越多，孤立块里的工作量被浪费，安全性被稀释。

2. GHOST 协议（以太坊早期）：
   选"包含最多区块的子树"对应的 tip，并且把孤立块作为"叔块(uncle)"引用进主链，
   给叔块矿工少量奖励。这样即使分叉频繁，安全性仍然累积到主链，
   允许以太坊用更短的出块时间（14 秒）而不损失安全性。

本模块模拟一个分叉场景，对比两种协议的选择结果，并演示双花攻击。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class BlockNode:
    height: int
    block_id: str          # 唯一标识，例如 "h3-A"
    parent: Optional["BlockNode"] = None
    miner: str = ""
    timestamp: float = field(default_factory=time.time)
    # 叔块引用：GHOST 协议用
    uncles: List["BlockNode"] = field(default_factory=list)

    @property
    def chain(self) -> List["BlockNode"]:
        """从创世块到本节点的完整链。"""
        nodes: List[BlockNode] = []
        cur: Optional[BlockNode] = self
        while cur is not None:
            nodes.append(cur)
            cur = cur.parent
        return list(reversed(nodes))

    @property
    def work(self) -> int:
        """累积工作量：在难度一致时等于高度+1。"""
        return self.height + 1


class ForkedChain:
    """维护一个有分叉的区块树。"""

    def __init__(self) -> None:
        self.by_id: Dict[str, BlockNode] = {}
        self.by_height: Dict[int, List[BlockNode]] = {}
        genesis = BlockNode(height=0, block_id="genesis", miner="sys")
        self.add_block(genesis)

    def add_block(self, node: BlockNode) -> None:
        self.by_id[node.block_id] = node
        self.by_height.setdefault(node.height, []).append(node)

    def tips(self) -> List[BlockNode]:
        """所有没有子节点的 tip。"""
        child_ids = {n.parent.block_id for n in self.by_id.values() if n.parent is not None}
        return [n for n in self.by_id.values() if n.block_id not in child_ids]

    def choose_longest_chain(self) -> BlockNode:
        tips = self.tips()
        return max(tips, key=lambda n: (n.work, n.timestamp))

    def choose_ghost(self) -> BlockNode:
        subtree_size: Dict[str, int] = {}
        for h in sorted(self.by_height.keys(), reverse=True):
            for node in self.by_height[h]:
                size = 1
                for child in self.by_id.values():
                    if child.parent is node:
                        size += subtree_size.get(child.block_id, 0)
                subtree_size[node.block_id] = size
        cur = self.by_id["genesis"]
        while True:
            children = [n for n in self.by_id.values() if n.parent is cur]
            if not children:
                return cur
            cur = max(children, key=lambda c: subtree_size[c.block_id])

    def attach_uncles(self, tip: BlockNode, max_uncles: int = 2) -> None:
        for h in range(1, tip.height + 1):
            for node in self.by_height.get(h, []):
                if node not in tip.chain and len(tip.uncles) < max_uncles:
                    tip.uncles.append(node)


def build_fork_scenario() -> ForkedChain:
    chain = ForkedChain()
    g = chain.by_id["genesis"]
    h1a = BlockNode(1, "h1-A", parent=g, miner="A")
    chain.add_block(h1a)
    h2a1 = BlockNode(2, "h2-A1", parent=h1a, miner="A")
    h2b = BlockNode(2, "h2-B", parent=h1a, miner="B")
    chain.add_block(h2a1)
    chain.add_block(h2b)
    h3a1a = BlockNode(3, "h3-A1a", parent=h2a1, miner="A")
    h3b1 = BlockNode(3, "h3-B1", parent=h2b, miner="B")
    chain.add_block(h3a1a)
    chain.add_block(h3b1)
    h4b1a = BlockNode(4, "h4-B1a", parent=h3b1, miner="B")
    chain.add_block(h4b1a)
    return chain


def build_double_spend_attack() -> ForkedChain:
    chain = ForkedChain()
    g = chain.by_id["genesis"]
    h1 = BlockNode(1, "honest-h1", parent=g, miner="honest")
    h2 = BlockNode(2, "honest-h2", parent=h1, miner="honest")
    h3 = BlockNode(3, "honest-h3(T)", parent=h2, miner="honest")
    h4 = BlockNode(4, "honest-h4", parent=h3, miner="honest")
    h5 = BlockNode(5, "honest-h5", parent=h4, miner="honest")
    for n in [h1, h2, h3, h4, h5]:
        chain.add_block(n)
    for i in range(2):
        chain.add_block(BlockNode(1, f"orphan-h1-{i}", parent=g, miner="honest-other"))
    for i in range(2):
        chain.add_block(BlockNode(2, f"orphan-h2-{i}", parent=h1, miner="honest-other"))
    for i in range(2):
        chain.add_block(BlockNode(3, f"orphan-h3-{i}", parent=h2, miner="honest-other"))
    for i in range(2):
        chain.add_block(BlockNode(4, f"orphan-h4-{i}", parent=h3, miner="honest-other"))
    a3 = BlockNode(3, "attack-h3*", parent=h2, miner="attacker")
    a4 = BlockNode(4, "attack-h4*", parent=a3, miner="attacker")
    a5 = BlockNode(5, "attack-h5*", parent=a4, miner="attacker")
    a6 = BlockNode(6, "attack-h6*", parent=a5, miner="attacker")
    a7 = BlockNode(7, "attack-h7*", parent=a6, miner="attacker")
    for n in [a3, a4, a5, a6, a7]:
        chain.add_block(n)
    return chain


def main() -> None:
    print("=" * 72)
    print("场景 1：正常分叉下，最长链 vs GHOST 的选择")
    print("=" * 72)
    chain = build_fork_scenario()
    lc = chain.choose_longest_chain()
    gh = chain.choose_ghost()
    print(f"  最长链原则选中 tip = {lc.block_id} (高度 {lc.height})")
    print(f"  GHOST 协议选中 tip = {gh.block_id} (高度 {gh.height})")
    chain.attach_uncles(gh)
    print(f"  GHOST 给 tip 挂了 {len(gh.uncles)} 个叔块")
    print()
    print("=" * 72)
    print("场景 2：双花攻击 —— 攻击者私有链公开后")
    print("=" * 72)
    attack_chain = build_double_spend_attack()
    lc2 = attack_chain.choose_longest_chain()
    gh2 = attack_chain.choose_ghost()
    print(f"  最长链原则选中 tip = {lc2.block_id} (高度 {lc2.height})")
    print(f"  GHOST 协议选中 tip = {gh2.block_id} (高度 {gh2.height})")


if __name__ == "__main__":
    main()
