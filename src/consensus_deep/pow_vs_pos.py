"""PoW vs PoS 共识对比：出块时间 / 能耗 / 分叉概率。

设计要点（对齐以太坊 / 比特币真实模型）：
- PoW：矿工反复对区块头做 SHA256，直到结果落在 target 以下。
  难度 target 决定了单次哈希命中概率 p = target / 2^256，
  期望需要 1/p 次哈希才能出块。
- PoS：协议按 slot 把出块权分配给验证者，选中概率正比于质押量。
  验证者不需要暴力哈希，一次抽样即完成，能耗近似为零。

零依赖：仅用 hashlib / random / time / dataclasses。
"""

from __future__ import annotations

import hashlib
import os
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Tuple


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def target_from_leading_zeros(hex_zeros: int) -> int:
    return 1 << (8 * (32 - hex_zeros // 2)) - 1 if hex_zeros > 0 else (1 << 256) - 1


@dataclass
class PoWMiner:
    miner_id: str
    hashrate_hps: int
    j_per_hash: float = 1e-8

    def mine(self, block_header: bytes, target: int,
             deadline: float = 5.0) -> Tuple[int, bytes, int]:
        nonce = random.randint(0, 2**32)
        hash_count = 0
        start = time.perf_counter()
        while True:
            h = sha256(block_header + nonce.to_bytes(32, "big"))
            hash_count += 1
            if int.from_bytes(h, "big") < target:
                return nonce, h, hash_count
            nonce += 1
            if time.perf_counter() - start > deadline:
                raise TimeoutError(
                    f"[{self.miner_id}] deadline={deadline}s 内未找到合法 nonce"
                )

    def energy_joules(self, hash_count: int) -> float:
        return hash_count * self.j_per_hash


@dataclass
class PoSValidator:
    validator_id: str
    stake: float

    def qualifies(self, seed: bytes, total_stake: float,
                  slot: int, slash_rate: float = 0.0) -> bool:
        if total_stake <= 0 or self.stake <= 0:
            return False
        h = sha256(seed + self.validator_id.encode() + slot.to_bytes(8, "big"))
        r = int.from_bytes(h, "big") / (1 << 256)
        threshold = self.stake / total_stake
        if r < threshold and random.random() > slash_rate:
            return True
        return False


@dataclass
class ConsensusStats:
    algorithm: str
    block_times: List[float] = field(default_factory=list)
    total_hash_count: int = 0
    total_joules: float = 0.0
    forks: int = 0
    blocks: int = 0

    @property
    def avg_block_time(self) -> float:
        return sum(self.block_times) / max(len(self.block_times), 1)

    def report(self) -> str:
        kwh = self.total_joules / 3.6e6
        return (
            f"[{self.algorithm}] blocks={self.blocks} | "
            f"avg_block_time={self.avg_block_time*1000:.1f}ms | "
            f"forks={self.forks} | hashes={self.total_hash_count:,} | "
            f"energy={kwh:.6f} kWh"
        )


def simulate_pow(miners: List[PoWMiner], n_blocks: int,
                 difficulty_hex_zeros: int = 2,
                 network_delay_ms: float = 50.0) -> ConsensusStats:
    target = target_from_leading_zeros(difficulty_hex_zeros)
    stats = ConsensusStats(algorithm="PoW")
    prev_hash = b"\x00" * 32
    for slot in range(n_blocks):
        header = prev_hash + slot.to_bytes(8, "big")
        best: Tuple[float, PoWMiner, int, bytes, int] = (1e9, None, 0, b"", 0)
        for m in miners:
            t0 = time.perf_counter()
            try:
                nonce, h, hc = m.mine(header, target, deadline=10.0)
            except TimeoutError:
                continue
            dt = time.perf_counter() - t0
            if dt < best[0]:
                best = (dt, m, nonce, h, hc)
        dt, winner, nonce, h, hc = best
        if winner is None:
            continue
        stats.block_times.append(dt)
        stats.total_hash_count += hc
        stats.total_joules += winner.energy_joules(hc)
        stats.blocks += 1
        prev_hash = h
        if stats.blocks > 1:
            avg_t = stats.avg_block_time
            fork_prob = min(network_delay_ms / 1000.0 / max(avg_t, 1e-6), 0.5)
            if random.random() < fork_prob:
                stats.forks += 1
    return stats


def simulate_pos(validators: List[PoSValidator], n_blocks: int,
                 network_delay_ms: float = 50.0) -> ConsensusStats:
    stats = ConsensusStats(algorithm="PoS")
    total_stake = sum(v.stake for v in validators)
    seed = os.urandom(32)
    slot_time = 2.0
    for slot in range(n_blocks):
        t0 = time.perf_counter()
        winner = None
        for v in validators:
            if v.qualifies(seed, total_stake, slot):
                winner = v
                break
        if winner is None:
            winner = max(validators, key=lambda x: x.stake)
        dt = time.perf_counter() - t0
        stats.block_times.append(slot_time)
        stats.total_hash_count += 1
        stats.total_joules += 1e-8
        stats.blocks += 1
        if random.random() < 0.005:
            stats.forks += 1
        seed = sha256(seed + slot.to_bytes(8, "big"))
    return stats


def main() -> None:
    print("=" * 78)
    print("MiniChain 共识对比：PoW vs PoS")
    print("=" * 78)
    miners = [
        PoWMiner("miner-A", hashrate_hps=200_000),
        PoWMiner("miner-B", hashrate_hps=150_000),
        PoWMiner("miner-C", hashrate_hps=100_000),
    ]
    validators = [
        PoSValidator("val-1", stake=32.0),
        PoSValidator("val-2", stake=64.0),
        PoSValidator("val-3", stake=16.0),
        PoSValidator("val-4", stake=128.0),
        PoSValidator("val-5", stake=32.0),
    ]
    print("\n[1] 跑 PoW：10 个块")
    pow_stats = simulate_pow(miners, n_blocks=10, difficulty_hex_zeros=2)
    print("   ->", pow_stats.report())
    print("\n[2] 跑 PoS：10 个块")
    pos_stats = simulate_pos(validators, n_blocks=10)
    print("   ->", pos_stats.report())


if __name__ == "__main__":
    main()
