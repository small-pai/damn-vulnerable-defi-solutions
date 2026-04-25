# Unstoppable 题解

## 一、题目简介

Unstoppable 是 Damn Vulnerable DeFi v4 的第一道入门题，合约基于标准 **ERC4626 金库协议** 开发，额外实现了 ERC3156 闪电贷功能。

题目目标：利用合约漏洞，使整个金库协议永久失效，存款、取款、闪电贷等所有核心功能无法调用，完成 DoS（拒绝服务）攻击。

核心特点：无需权限、无需复杂攻击逻辑、仅单次转账即可永久瘫痪协议。

## 二、合约核心逻辑梳理

本次题目核心合约：`src/unstoppable/UnstoppableVault\.sol`

合约关键机制：

1. 遵循 ERC4626 规范，通过**份额（share）**与**资产（asset）**的汇率，实现用户存取款；

2. 实现闪电贷功能，所有闪电贷调用前会执行一次强制校验；

3. `totalAssets()` 直接读取链上代币真实余额，作为金库总资产。

## 三、漏洞定位与原理分析

### 1\. 漏洞关键代码

漏洞存在于 `flashLoan` 闪电贷函数中，核心校验代码：

```solidity
uint256 balanceBefore = totalAssets();
if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance();
```

### 2\. 代码释义

- `balanceBefore`：金库**链上真实代币余额**（客观数据，区块链不可篡改）；

- `convertToShares\(totalSupply\)`：将金库**全部发行的用户份额**，换算为对应的代币资产数量；

- 合约强制要求：**份额换算后的资产数量 必须严格等于 链上真实余额**，一旦不相等，直接回滚报错。

### 3\. 漏洞核心成因

ERC20 代币原生支持 `transfer` 转账，攻击者可以**不经过合约任何业务函数（deposit/闪电贷）**，直接向金库合约地址转账代币。

这会造成致命的数据错位：

1. 正规用户存款：调用 `deposit`，合约同时**增加代币余额 \+ 增发用户份额**，两者数据同步；

2. 攻击者直接转账：仅增加合约链上代币余额，**不会增发任何份额**。

最终导致：`真实资产余额 > 份额换算资产数量`，永久触发 `InvalidBalance` 报错。

### 4\. 漏洞危害

该校验属于全局强校验，不仅闪电贷无法调用，合约存取款等所有依赖资产、份额校验的功能都会全部失效，直接造成**永久性 DoS 拒绝服务攻击**，协议彻底瘫痪。

## 四、审计挖洞思路

新手/审计人员遇到 ERC4626 金库合约，优先扫描以下 **高危关键词组合**，可快速定位同款漏洞：

1. `totalAssets()`：读取合约真实链上余额；

2. `convertToShares`：份额与资产换算逻辑；

3. `totalSupply`：合约总发行份额；

4. 等值强校验（`\!=`、`==`）。

只要合约**强制绑定份额总量与链上真实资产余额**，且无外部转账隔离逻辑，百分百存在 DoS 漏洞。

## 五、攻击 EXP

攻击文件路径：`test/unstoppable/Unstoppable\.t\.sol`

一行核心代码，破坏数据一致性通关：

```solidity
function exploit() internal override {
    // 直接向金库转账1枚代币，破坏份额与资产的一致性
    token.transfer(address(vault), 1);
}
```

## 六、运行命令与通关结果

### 运行命令

```bash
forge test --match-contract UnstoppableChallenge
```

### 通关结果

```Plain Text
[PASS] test_assertInitialState()
[PASS] test_unstoppable()
Suite result: ok. 2 passed; 0 failed; 0 skipped
```

## 七、漏洞修复方案

1. **移除全局强等值校验**：不要强制要求份额总量与链上资产完全一致，外部转账属于正常链上行为，无需拦截业务逻辑；

2. **区分用户存款与外部捐赠转账**：新增内部记账变量，仅统计用户通过 `deposit` 存入的资产，忽略外部直接转账；

3. **弱化报错机制**：禁止使用严苛的全局等值 revert 校验，避免单次数据不一致导致整个协议瘫痪。

## 八、题目总结

本题是 DeFi 安全的**账本不一致 DoS 漏洞**。核心误区是合约过度自信，强制要求链上资产与合约记账数据绝对一致，忽略了 ERC20 可直接转账、无需合约授权的原生特性。

该漏洞覆盖绝大多数 ERC4626 金库合约，是合约审计、DeFi CTF 必备知识点。

