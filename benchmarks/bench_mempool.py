"""Benchmark 2：交易池策略对比 —— FIFO vs Gas 溢价优先。

问题：节点从 mempool 选交易打包时，
- FIFO：按到达顺序打包，简单，但高 gas 用户被低 gas 用户堵塞。
- Gas 溢价优先：每次选 gas_price 最高的交易打包，优先满足高付费用户。

指标：
- 平均确认延迟（交易从进入 mempool 到被打包经过多少块）
- 高 gas 交易延迟
- 低 gas 交易饿死率
- Gas 收入（节点手续费总收入）
"""

from __future__ import annotations

import os
import random
import sys
from dataclasses import dataclass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))


@dataclass
class Tx:
    tx_id: int
    gas_price: int
    arrive_block: int
    packed_block: int = -1


def generate_mempool(n: int, seed: int = 42) -> list:
    random.seed(seed)
    # 双峰分布：20% 高付费（50-100），80% 低付费（1-10）
    txs = []
    for i in range(n):
        if random.random() < 0.2:
            gp = random.randint(50, 100)
        else:
            gp = random.randint(1, 10)
        txs.append(Tx(
            tx_id=i,
            gas_price=gp,
            arrive_block=random.randint(0, 50),
        ))
    return txs


def simulate_fifo(txs: list, block_size: int = 20, max_blocks: int = 200) -> dict:
    """FIFO：按到达顺序打包；时间逐块推进，每块只选已到达交易。"""
    pending = sorted(txs, key=lambda t: t.arrive_block)
    block = 0
    gas_income = 0
    idx = 0
    while block < max_blocks and idx < len(pending):
        block += 1
        chosen = 0
        while idx < len(pending) and chosen < block_size:
            tx = pending[idx]
            if tx.arrive_block > block:
                break
            tx.packed_block = block
            gas_income += tx.gas_price
            idx += 1
            chosen += 1
    return _stats(txs, gas_income)


def simulate_gas_priority(txs: list, block_size: int = 20, max_blocks: int = 200) -> dict:
    """Gas 溢价优先：每轮选 gas_price 最高的已到达交易。"""
    pending = list(txs)
    block = 0
    gas_income = 0
    while block < max_blocks and pending:
        block += 1
        ready = [t for t in pending if t.arrive_block <= block]
        ready.sort(key=lambda t: -t.gas_price)
        chosen = ready[:block_size]
        for tx in chosen:
            tx.packed_block = block
            gas_income += tx.gas_price
            pending.remove(tx)
        if not ready:
            continue
    return _stats(txs, gas_income)


def _stats(txs: list, gas_income: int) -> dict:
    delays = [t.packed_block - t.arrive_block for t in txs]
    avg_delay = sum(delays) / len(delays)
    high_gas = [t for t in txs if t.gas_price >= 50]
    high_gas_delay = sum(t.packed_block - t.arrive_block for t in high_gas) / max(len(high_gas), 1)
    low_gas = [t for t in txs if t.gas_price < 5]
    low_starved = sum(1 for t in low_gas if t.packed_block - t.arrive_block > 30)
    return {
        "avg_delay_blocks": avg_delay,
        "high_gas_delay": high_gas_delay,
        "low_gas_starved_pct": low_starved / max(len(low_gas), 1) * 100,
        "gas_income": gas_income,
    }


def main() -> None:
    print("=" * 78)
    print("Benchmark 2：交易池策略对比（2000 笔交易，每块 20 笔）")
    print("=" * 78)

    txs_fifo = generate_mempool(2000)
    txs_gas = generate_mempool(2000)

    s_fifo = simulate_fifo(txs_fifo)
    s_gas = simulate_gas_priority(txs_gas)

    print(f"\n{'指标':<28}{'FIFO':>16}{'Gas 溢价优先':>16}")
    print("-" * 64)
    print(f"{'平均确认延迟 (块)':<28}{s_fifo['avg_delay_blocks']:>16.2f}{s_gas['avg_delay_blocks']:>16.2f}")
    print(f"{'高 gas 交易延迟 (块)':<28}{s_fifo['high_gas_delay']:>16.2f}{s_gas['high_gas_delay']:>16.2f}")
    print(f"{'低 gas 交易饿死率 (%)':<28}{s_fifo['low_gas_starved_pct']:>16.1f}{s_gas['low_gas_starved_pct']:>16.1f}")
    print(f"{'节点 Gas 收入':<28}{s_fifo['gas_income']:>16,}{s_gas['gas_income']:>16,}")

    print("\n结论：")
    print("  - FIFO 公平但高 gas 用户被低 gas 用户堵塞，体验差")
    print("  - Gas 溢价优先让高付费用户立即确认，但低付费交易饿死")
    print("  - 现实以太坊用 EIP-1559 base fee + priority fee 折中")


if __name__ == "__main__":
    main()
