"""Benchmark 1：PoW vs PoS 共识对比。

指标：
- 出块时间（毫秒）
- 能耗（焦耳）
- 吞吐量（TPS，假设每块 100 笔交易）
- 分叉率
"""

from __future__ import annotations

import os
import sys
import time

# 把 src 加入 import 路径
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from consensus_deep.pow_vs_pos import (  # noqa: E402
    PoWMiner, PoSValidator, simulate_pow, simulate_pos,
)


def main() -> None:
    print("=" * 78)
    print("Benchmark 1：PoW vs PoS 共识对比")
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

    t0 = time.perf_counter()
    pow_stats = simulate_pow(miners, n_blocks=15, difficulty_hex_zeros=2)
    pow_wall = time.perf_counter() - t0

    t0 = time.perf_counter()
    pos_stats = simulate_pos(validators, n_blocks=15)
    pos_wall = time.perf_counter() - t0

    print(f"\n{'指标':<24}{'PoW':>18}{'PoS':>18}")
    print("-" * 60)
    print(f"{'块数':<24}{pow_stats.blocks:>18}{pos_stats.blocks:>18}")
    print(f"{'平均出块时间 (ms)':<24}{pow_stats.avg_block_time*1000:>18.2f}{pos_stats.avg_block_time*1000:>18.2f}")
    print(f"{'分叉率 (%)':<24}{pow_stats.forks/pow_stats.blocks*100:>18.1f}{pos_stats.forks/pos_stats.blocks*100:>18.1f}")
    print(f"{'总哈希次数':<24}{pow_stats.total_hash_count:>18,}{pos_stats.total_hash_count:>18,}")
    print(f"{'总能耗 (焦耳)':<24}{pow_stats.total_joules:>18.4e}{pos_stats.total_joules:>18.4e}")
    print(f"{'估算 TPS':<24}{pow_stats.tps_approx:>18.1f}{pos_stats.tps_approx:>18.1f}")
    print(f"{'墙钟时间 (秒)':<24}{pow_wall:>18.2f}{pos_wall:>18.2f}")

    print("\n结论：PoS 在能耗和出块时间方差上碾压 PoW；")
    print("PoW 的安全性来自算力消耗，PoS 的安全性来自质押惩罚。")


if __name__ == "__main__":
    main()
