# MiniChain 迷你公链

对标以太坊核心机制的教学级实现，覆盖共识、区块验证、分叉解决、Gas 模型、迷你 EVM、MPT 状态树六大模块。所有代码零外部依赖（仅 Python 标准库），可直接运行。

## 目录结构

```
MiniChain迷你公链/
├── src/
│   ├── consensus_deep/            # 共识深度模块
│   │   ├── pow_vs_pos.py          # PoW vs PoS 对比：出块时间/能耗/分叉概率
│   │   ├── block_validation.py     # 区块验证：哈希/签名/Merkle 树
│   │   └── fork_resolution.py     # 分叉解决：最长链 vs GHOST
│   └── smartcontract_deep/         # 智能合约深度模块
│       ├── gas_model.py           # Gas 计费：操作码定价 + 超限拒绝
│       ├── vm_executor.py         # 迷你 EVM：PUSH/POP/ADD/SSTORE
│       └── state_trie.py          # MPT 状态树：root hash + 增量更新
├── benchmarks/                     # 4 组性能基准
│   ├── bench_consensus.py          # PoW vs PoS：出块/能耗/TPS
│   ├── bench_mempool.py            # FIFO vs Gas 优先：确认延迟/饿死率
│   ├── bench_gas_opcodes.py        # 操作码 Gas 消耗与执行耗时
│   └── bench_throughput.py         # 100/1K/10K 交易 TPS
└── docs/
    └── pitfalls/                   # 5 份六段式踩坑文档
        ├── 01_区块哈希计算错误.md
        ├── 02_交易签名验证失败.md
        ├── 03_分叉双花攻击.md
        ├── 04_Gas估算不准.md
        └── 05_状态树不一致.md
```

## 快速运行

```bash
# 核心模块 demo
python src/consensus_deep/pow_vs_pos.py
python src/consensus_deep/block_validation.py
python src/consensus_deep/fork_resolution.py
python src/smartcontract_deep/gas_model.py
python src/smartcontract_deep/vm_executor.py
python src/smartcontract_deep/state_trie.py

# 4 组 benchmark
python benchmarks/bench_consensus.py
python benchmarks/bench_mempool.py
python benchmarks/bench_gas_opcodes.py
python benchmarks/bench_throughput.py
```

## 技术亮点

### 共识模块
- **PoW**：SHA256 暴力哈希，难度目标用前导零数控制，能耗按 ASIC 实测 ~1e-8 J/hash 估算
- **PoS**：RANDAO 抽签，中签概率正比于质押量，slot 固定出块
- **分叉解决**：最长链（Nakamoto）vs GHOST（子树权重 + 叔块），仿真双花攻击场景

### 区块验证
- 完整流水线：prev_hash 链接 → 高度连续 → Merkle Root 重算 → PoW 难度 → 签名验签 → 时间戳窗口
- 签名后端自动降级：有 `ecdsa` 库用 secp256k1，否则用 HMAC 教学签名
- Merkle SPV 证明：`proof()` / `verify()` 实现轻节点校验

### 智能合约
- **Gas 模型**：对齐伦敦升级后定价，SLOAD warm 800 / cold 21000，SSTORE 新增 20000 / 修改 5000
- **迷你 EVM**：栈（1024 上限）+ 内存 + 持久存储，支持 20 个操作码，JUMPDEST 防跳转攻击
- **MPT 状态树**：leaf/extension/branch 三类节点，HP 编码，不可变更新（旧 root 保留为历史快照）

## 面试话术速记

| 模块 | 一句话核心 |
|------|-----------|
| PoW vs PoS | PoW 安全靠算力消耗，PoS 安全靠质押惩罚（slashing） |
| 区块验证 | 哈希输入必须逐字节确定，JSON 序列化是大坑，要用 RLP |
| 分叉解决 | 最长链简单但分叉时浪费算力；GHOST 把孤立块计入子树权重 |
| Gas 模型 | SSTORE/SLOAD 是最贵操作码，合约优化核心是减少存储写入 |
| EVM | 栈机 + 256-bit word，gas 耗尽即回滚状态但不退手续费 |
| MPT | root hash 不仅依赖 key/value，还依赖树结构，必须严格按黄皮书实现 |
