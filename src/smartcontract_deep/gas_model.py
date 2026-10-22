"""Gas 计费模型：操作码 Gas 消耗 + 超限拒绝。

以太坊为什么需要 Gas？
- 如果执行智能合约免费，恶意矿工可以部署死循环合约让全节点 CPU 跑满。
  Gas 给每一步计算定价，用户为计算付费，节点为计算收费。

Gas 组成：
  1. 内在 Gas：交易本身的固定开销（21000）。
  2. Calldata Gas：携带的数据按字节计费。
  3. 执行 Gas：每条操作码执行时扣减。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


OPCODE_GAS: Dict[str, int] = {
    "STOP": 0, "POP": 2,
    "PUSH1": 3, "PUSH2": 3, "PUSH3": 3, "PUSH4": 3, "PUSH32": 3,
    "ADD": 3, "SUB": 3, "NOT": 3,
    "MUL": 5, "DIV": 5, "MOD": 5,
    "LT": 3, "GT": 3, "EQ": 3, "ISZERO": 3,
    "MLOAD": 3, "MSTORE": 3, "MSTORE8": 3,
    "SLOAD": 800, "SSTORE": 5000,
    "JUMP": 8, "JUMPI": 10, "PC": 2, "JUMPDEST": 1,
    "SHA3": 30,
    "RETURN": 0, "REVERT": 0,
}

TX_INTRINSIC_GAS = 21000
CALLDATA_ZERO_BYTE_GAS = 4
CALLDATA_NONZERO_BYTE_GAS = 16
COLD_SLOAD_GAS = 21000


class OutOfGasError(Exception):
    pass


@dataclass
class GasMeter:
    gas_limit: int
    gas_used: int = 0
    warm_storage: set = field(default_factory=set)

    def remaining(self) -> int:
        return self.gas_limit - self.gas_used

    def _charge(self, amount: int) -> None:
        if self.gas_used + amount > self.gas_limit:
            raise OutOfGasError(
                f"gas 耗尽：已用 {self.gas_used}，限额 {self.gas_limit}"
            )
        self.gas_used += amount

    def consume_opcode(self, opcode: str, *,
                      is_new_key: bool = False,
                      is_cold: bool = False,
                      memory_words: int = 0) -> int:
        if opcode == "SLOAD":
            amount = COLD_SLOAD_GAS if is_cold else OPCODE_GAS["SLOAD"]
        elif opcode == "SSTORE":
            amount = 20000 if is_new_key else OPCODE_GAS["SSTORE"]
        elif opcode == "SHA3":
            amount = OPCODE_GAS["SHA3"] + 6 * max(memory_words, 0)
        else:
            amount = OPCODE_GAS.get(opcode, 0)
        self._charge(amount)
        return amount


def intrinsic_gas(calldata: bytes, *, contract_creation: bool = False) -> int:
    gas = TX_INTRINSIC_GAS
    if contract_creation:
        gas += 32000
    for byte in calldata:
        gas += CALLDATA_ZERO_BYTE_GAS if byte == 0 else CALLDATA_NONZERO_BYTE_GAS
    return gas


def main() -> None:
    print("=" * 70)
    print("Gas 计费模型演示")
    print("=" * 70)
    print(f"\n[1] 普通转账 intrinsic_gas = {intrinsic_gas(b''):,}")
    calldata = bytes([0xa9, 0x05, 0x9c, 0xbb, 0x00, 0x00, 0x00, 0x2a])
    print(f"[2] 合约调用 intrinsic_gas = {intrinsic_gas(calldata):,}")
    print("\n[3] 模拟 EVM 执行")
    meter = GasMeter(gas_limit=100_000)
    for op, kw in [("PUSH1", {}), ("PUSH1", {}), ("ADD", {}),
                   ("PUSH1", {}), ("SSTORE", {"is_new_key": True})]:
        cost = meter.consume_opcode(op, **kw)
        print(f"    {op:8s} 消耗 {cost:>6} gas，累计 {meter.gas_used:>6}")
    print(f"    剩余 gas = {meter.remaining()}")


if __name__ == "__main__":
    main()
