## Possible Solutions for Cryptographic Defects

| Type | Possible Solutions for Cryptographic Defects                 |
| ---- | ------------------------------------------------------------ |
| SSR  | Include a monotonic increasing nonce into the signed message. |
| CSR  | Include the contract address into the signed message.        |
| SF   | Prevent front-run signatures from causing unintended behaviors. |
| SM   | Add protection against ECDSA signature malleability.         |
| ISV  | Check the return value of Ecrecover before sensitive operations. |
| MR   | Check if the Merkle proof has been used before accepting it. |
| MF   | Prevent front-run Merkle proofs from causing unintended behaviors. |
| HC   | Use collision-resistant encoding to hash dynamic-length variables. |
| WR   | Use verifiable random function (VRF) for randomness.         |

## Example

For example, the following code segment is an ad-hoc implementation of the [ERC-20 permit extension](https://eips.ethereum.org/EIPS/eip-2612), suffering the SSR, CSR, and SF defects.

```solidity
function permit(address owner, uint256 value, uint256 deadline, uint8 v,bytes32 r, bytes32 s) external {
    bytes32 hash = keccak256(abi.encode(owner, value, deadline));
    address signer = ecrecover(hash, v, r, s);
    require(signer != address(0),"Invalid Signature");
    require(owner == signer, "Invalid Signer");
    require(block.timestamp<deadline, "Permit Expired");
    _approve(owner, msg.sender, value);}
```

The following figure shows a fixed version of this defective contract.

```solidity
function permit(address owner,address spender,uint256 value,uint256 deadline,uint8 v,bytes32 r,bytes32 s) public virtual {
    if (block.timestamp > deadline) {
        revert ERC2612ExpiredSignature(deadline);}
    bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, _useNonce(owner), deadline));
    bytes32 hash = _hashTypedDataV4(structHash);
    address signer = ECDSA.recover(hash, v, r, s);
    if (signer != owner) {
        revert ERC2612InvalidSigner(signer, owner);}
    _approve(owner, spender, value);}
```

It comes from a standard template, i.e., [openzepplin-erc20permit](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/extensions/ERC20Permit.sol) provided by OpenZeppelin, which employs the above solutions to prevent SSR, CSR, and SF defects.

It integrates a nonce in the signed message to prevent SSR defects (line 4). It also includes a domain separator containing the contract address into the signed message to prevent the CSR defects (line 5).

Furthermore, to address SF defects, it replaces the address to be approved (line 9) from *msg.sender* to the *spender* specified by the signature (line 4). It ensures that even if an attacker front-run the signature, he cannot change the intended contract behavior, i.e., *owner* approving *spender* for a certain *value* of tokens.