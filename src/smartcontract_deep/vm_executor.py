"""迷你 EVM 栈虚拟机：PUSH / POP / ADD / SSTORE 等操作码执行。

EVM 是一个基于栈的 256-bit 虚拟机：
- 栈深度上限 1024，每个 word 是 256-bit 无符号整数
- 内存是可扩展的字节数组
- 持久化存储（storage）是 key->value 的 key-value 映射
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from smartcontract_deep.gas_model import GasMeter, OutOfGasError  # noqa


OP_STOP = 0x00; OP_ADD = 0x01; OP_MUL = 0x02; OP_SUB = 0x03; OP_DIV = 0x04
OP_LT = 0x10; OP_GT = 0x11; OP_EQ = 0x14; OP_ISZERO = 0x15
OP_SHA3 = 0x20; OP_POP = 0x50; OP_MLOAD = 0x51; OP_MSTORE = 0x52
OP_SLOAD = 0x54; OP_SSTORE = 0x55
OP_JUMP = 0x56; OP_JUMPI = 0x57; OP_PC = 0x58; OP_JUMPDEST = 0x5B
OP_PUSH1 = 0x60; OP_PUSH2 = 0x61; OP_RETURN = 0xF3; OP_REVERT = 0xFD

STACK_LIMIT = 1024
WORD_SIZE = 32


class VMError(Exception):
    pass


@dataclass
class ExecutionResult:
    used_gas: int
    return_data: bytes
    storage_root: Dict[int, int]
    reverted: bool
    error: Optional[str] = None


@dataclass
class EVM:
    code: bytes
    storage: Dict[int, int] = field(default_factory=dict)
    _stack: List[int] = field(default_factory=list, repr=False)
    _memory: bytearray = field(default_factory=bytearray, repr=False)
    _pc: int = 0
    _meter: Optional[GasMeter] = None
    _return_data: bytes = b""

    def _push(self, value: int) -> None:
        value &= (1 << 256) - 1
        if len(self._stack) >= STACK_LIMIT:
            raise VMError("栈溢出")
        self._stack.append(value)

    def _pop(self) -> int:
        if not self._stack:
            raise VMError("栈下溢")
        return self._stack.pop()

    def _mload(self, offset: int) -> int:
        self._ensure_memory(offset + WORD_SIZE)
        return int.from_bytes(self._memory[offset:offset + WORD_SIZE], "big")

    def _mstore(self, offset: int, value: int) -> None:
        self._ensure_memory(offset + WORD_SIZE)
        self._memory[offset:offset + WORD_SIZE] = value.to_bytes(WORD_SIZE, "big")

    def _ensure_memory(self, size: int) -> None:
        if size > len(self._memory):
            self._memory.extend(b"\x00" * (size - len(self._memory)))

    def run(self, gas_limit: int = 1_000_000) -> ExecutionResult:
        self._meter = GasMeter(gas_limit=gas_limit)
        self._stack.clear(); self._memory.clear(); self._pc = 0
        self._return_data = b""
        snapshot = dict(self.storage)
        try:
            while True:
                if self._pc >= len(self.code):
                    raise VMError("PC 越界")
                op = self.code[self._pc]
                self._execute(op)
                if op in (OP_STOP, OP_RETURN, OP_REVERT):
                    break
        except (OutOfGasError, VMError) as e:
            self.storage.clear(); self.storage.update(snapshot)
            return ExecutionResult(
                used_gas=self._meter.gas_used, return_data=b"",
                storage_root=dict(self.storage), reverted=True, error=str(e))
        return ExecutionResult(
            used_gas=self._meter.gas_used, return_data=self._return_data,
            storage_root=dict(self.storage), reverted=False)

    def _execute(self, op: int) -> None:
        m = self._meter
        if op == OP_STOP: self._pc += 1
        elif op == OP_ADD:
            a, b = self._pop(), self._pop()
            m.consume_opcode("ADD"); self._push(a + b); self._pc += 1
        elif op == OP_SUB:
            a, b = self._pop(), self._pop()
            m.consume_opcode("SUB"); self._push(b - a); self._pc += 1
        elif op == OP_MUL:
            a, b = self._pop(), self._pop()
            m.consume_opcode("MUL"); self._push(a * b); self._pc += 1
        elif op == OP_LT:
            a, b = self._pop(), self._pop()
            m.consume_opcode("LT"); self._push(1 if b < a else 0); self._pc += 1
        elif op == OP_GT:
            a, b = self._pop(), self._pop()
            m.consume_opcode("GT"); self._push(1 if b > a else 0); self._pc += 1
        elif op == OP_EQ:
            a, b = self._pop(), self._pop()
            m.consume_opcode("EQ"); self._push(1 if a == b else 0); self._pc += 1
        elif op == OP_ISZERO:
            a = self._pop(); m.consume_opcode("ISZERO")
            self._push(1 if a == 0 else 0); self._pc += 1
        elif op == OP_POP:
            self._pop(); m.consume_opcode("POP"); self._pc += 1
        elif op == OP_PUSH1:
            self._pc += 1
            if self._pc >= len(self.code): raise VMError("PUSH1 操作数缺失")
            value = self.code[self._pc]
            m.consume_opcode("PUSH1"); self._push(value); self._pc += 1
        elif op == OP_PUSH2:
            self._pc += 1
            if self._pc + 1 >= len(self.code): raise VMError("PUSH2 操作数缺失")
            value = int.from_bytes(self.code[self._pc:self._pc + 2], "big")
            m.consume_opcode("PUSH2"); self._push(value); self._pc += 2
        elif op == OP_MLOAD:
            offset = self._pop(); m.consume_opcode("MLOAD")
            self._push(self._mload(offset)); self._pc += 1
        elif op == OP_MSTORE:
            offset, value = self._pop(), self._pop(); m.consume_opcode("MSTORE")
            self._mstore(offset, value); self._pc += 1
        elif op == OP_SLOAD:
            key = self._pop()
            is_cold = key not in self._meter.warm_storage
            m.consume_opcode("SLOAD", is_cold=is_cold)
            self._meter.warm_storage.add(key)
            self._push(self.storage.get(key, 0)); self._pc += 1
        elif op == OP_SSTORE:
            key, value = self._pop(), self._pop()
            is_new_key = key not in self.storage
            m.consume_opcode("SSTORE", is_new_key=is_new_key)
            self._meter.warm_storage.add(key)
            self.storage[key] = value; self._pc += 1
        elif op == OP_SHA3:
            offset, size = self._pop(), self._pop()
            self._ensure_memory(offset + size)
            preimage = bytes(self._memory[offset:offset + size])
            m.consume_opcode("SHA3", memory_words=(size + 31) // 32)
            self._push(int.from_bytes(hashlib.sha256(preimage).digest(), "big"))
            self._pc += 1
        elif op == OP_JUMP:
            dest = self._pop(); m.consume_opcode("JUMP"); self._jump_to(dest)
        elif op == OP_JUMPI:
            dest, cond = self._pop(), self._pop()
            m.consume_opcode("JUMPI")
            if cond != 0: self._jump_to(dest)
            else: self._pc += 1
        elif op == OP_JUMPDEST:
            m.consume_opcode("JUMPDEST"); self._pc += 1
        elif op == OP_PC:
            m.consume_opcode("PC"); self._push(self._pc); self._pc += 1
        elif op == OP_RETURN:
            size, offset = self._pop(), self._pop()
            m.consume_opcode("RETURN")
            self._ensure_memory(offset + size)
            self._return_data = bytes(self._memory[offset:offset + size])
            self._pc += 1
        elif op == OP_REVERT:
            m.consume_opcode("REVERT"); self._return_data = b""; self._pc += 1
        else:
            raise VMError(f"未知操作码 0x{op:02x} @ PC={self._pc}")

    def _jump_to(self, dest: int) -> None:
        if dest >= len(self.code) or self.code[dest] != OP_JUMPDEST:
            raise VMError(f"无效跳转：目标 {dest} 不是 JUMPDEST")
        self._pc = dest


def compile_simple_program(ops: List[tuple]) -> bytes:
    out = bytearray()
    for op, operand in ops:
        out.append(op)
        if op == OP_PUSH1: out.append(operand or 0)
        elif op == OP_PUSH2: out.extend((operand or 0).to_bytes(2, "big"))
    return bytes(out)


def main() -> None:
    print("=" * 70)
    print("迷你 EVM 执行演示")
    print("=" * 70)
    print("\n[1] 程序：2 + 3 = 5")
    code1 = compile_simple_program([
        (OP_PUSH1, 2), (OP_PUSH1, 3), (OP_ADD, None),
        (OP_PUSH1, 0), (OP_MSTORE, None),
        (OP_PUSH1, 0), (OP_PUSH1, 32), (OP_RETURN, None),
    ])
    r1 = EVM(code1).run(gas_limit=100_000)
    print(f"    reverted={r1.reverted}, used_gas={r1.used_gas}")
    print(f"    return = {int.from_bytes(r1.return_data, 'big')}")


if __name__ == "__main__":
    main()
