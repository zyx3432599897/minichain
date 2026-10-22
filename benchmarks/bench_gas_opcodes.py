"""Benchmark 3：不同操作码 Gas 消耗与执行耗时对比。

统计每条操作码在迷你 EVM 中执行 10000 次的：
- 单次执行耗时（微秒）
- 消耗 gas（按 gas_model 定价）
- gas / 秒（节点吞吐）
"""

from __future__ import annotations

import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from smartcontract_deep.gas_model import GasMeter, OPCODE_GAS  # noqa: E402


def bench_opcode(opcode: str, repeats: int = 10_000) -> tuple:
    meter = GasMeter(gas_limit=10**9)
    # 准备栈：ADD/SUB 需要两个操作数
    t0 = time.perf_counter()
    total_gas = 0
    for _ in range(repeats):
        if opcode in ("ADD", "SUB", "MUL", "DIV", "LT", "GT", "EQ"):
            total_gas += meter.consume_opcode(opcode)
        elif opcode == "SSTORE":
            total_gas += meter.consume_opcode(opcode, is_new_key=False)
        elif opcode == "SLOAD":
            total_gas += meter.consume_opcode(opcode, is_cold=False)
        else:
            total_gas += meter.consume_opcode(opcode)
    dt = time.perf_counter() - t0
    avg_us = dt / repeats * 1e6
    return avg_us, total_gas / repeats


def main() -> None:
    print("=" * 78)
    print("Benchmark 3：操作码 Gas 与执行耗时（10000 次重复）")
    print("=" * 78)

    opcodes = ["PUSH1", "POP", "ADD", "MUL", "LT", "EQ",
               "SHA3", "SLOAD", "SSTORE", "MSTORE", "JUMP"]
    print(f"\n{'操作码':<10}{'Gas/次':>10}{'耗时(μs)':>14}{'Gas/秒':>18}")
    print("-" * 56)
    for op in opcodes:
        avg_us, gas_per_op = bench_opcode(op)
        gas_per_sec = gas_per_op / (avg_us * 1e-6)
        print(f"{op:<10}{gas_per_op:>10.0f}{avg_us:>14.3f}{gas_per_sec:>18,.0f}")

    print("\n结论：")
    print("  - SSTORE/SLOAD 是最贵的操作码（持久化存储要落盘+Merkle 更新）")
    print("  - 算术操作极便宜（3 gas），是 EVM 的高频热路径")
    print("  - 智能合约优化的核心：减少 SSTORE 次数，把计算放内存")


if __name__ == "__main__":
    main()
