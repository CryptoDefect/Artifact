# Case Study

This file studies several defective cases reported by CrySol. For more defective contracts, please refer to ``./Dataset1/``and ``./Dataset2/``.

## Case 1

**Contract: https://etherscan.io/address/0x25692da406889bf4db93f921063d9bc952bd01d0**

**Defect: Signature Front-Running**

**Impact: Allow unauthorized attackers to mint NFTs.**

**Defective Functions：**

```solidity
function recoverSigner(bytes32 hash, bytes memory signature)
    internal
    pure
    returns (address)
{
    bytes32 messageDigest = keccak256(
        abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
    );
    return ECDSA.recover(messageDigest, signature);
}
function getNFT(
    uint256 _mintNum,
    bytes32 hash,
    bytes memory signature
) public payable callerIsUser {
    uint256 supply = totalSupply();
    uint256 cost = getCost();
    uint256 allowedToMint = getAllowedTokens();

    require(allowlistSaleActive || publicSaleActive, "not ready for sale");
    require(supply + _mintNum <= maxSupply, "Supply Limit Reached");
    require(
        recoverSigner(hash, signature) == signerAddress,
        "User not allowed to mint tokens"
    );
    require(!signatureUsed[signature], "Signature has already been used.");
    require(
        allowedToMint >= _mintNum,
        "Can't mint more than allowed amount"
    );
    require(msg.value >= cost * _mintNum, "Not Enough Tokens");

    if (allowlistSaleActive) {
        _safeMint(msg.sender, _mintNum);
        AllowlistTokens[msg.sender] += _mintNum;
    } else if (publicSaleActive) {
        _safeMint(msg.sender, _mintNum);
        PublicSaleTokens[msg.sender] += _mintNum;
    }
    signatureUsed[signature] = true;
}
```

**Description:**

The expected behavior of this function is to allow users to mint an NFT by submitting a signature issued by "signerAddress". It uses the signature verification to enforce suchaccess control policy. However, in the `getNFT` function, the signature is vulnerable to being front-run by an attacker. By intercepting signatures from pending transactions and initiating a new transaction, the attacker can preemptively use the signature to mint the NFT. Furthermore, once the attacker successfully uses the signature and obtains the NFT, the signature will be marked as used. This prevents the original holder of the signature from using it to acquire the NFT again.

Similar defects can also be found in the following cases:

* https://etherscan.io/address/0xa82f049efc4c0af4f441c1c157d071441b2a49ca#code
* https://etherscan.io/address/0x626acf48a59d5dee6e4e7eb07386ad2851bcb5ce#code
* https://etherscan.io/address/0x48fe8692397772ecc0ab8f021159ccb26434da44#code

## Case 2

**Contract: https://etherscan.io/address/0x6137cbef171f49c58f92fa696f8fe053688fc93e#code**

**Defect:  Merkle Proof Replay**

**Impact: Allow attackers to make unauthorized/repeated accesss to sensitive operations.**

**Defective Functions：**

```solidity
  function mintOG(uint8 mintAmount, address _account, bytes32[] calldata _proof) public payable {
    require(sellingStep == Steps.WLMints, "WLMints has not started");
    require(totalSupply().add(mintAmount) <= MaxToken, "Sold Out");
    require(isOGWhitelisted(_account, _proof), "Not Whitelisted");
    require(MaxOgMint[msg.sender] + mintAmount <= 3, "Max NFTs Reached");
    require(mintAmount > 0, "At least one should be minted");
    MaxOgMint[msg.sender] += mintAmount;
    require(Price * mintAmount <= msg.value, "Not enough funds");
    if(totalSupply() + mintAmount == MaxToken) { sellingStep = Steps.SoldOut; }
    _mint(msg.sender, mintAmount);
    emit TokenMinted(totalSupply());
  }
    //// OG WHITELIST WALLETS
  function isOGWhitelisted(address account, bytes32[] calldata proof) internal view returns(bool) {
    return _verify(_leaf(account), proof);
  }

  function _verify(bytes32 leaf, bytes32[] memory proof) internal view returns(bool) {
    return MerkleProof.verify(proof, merkleRootOG, leaf);
  }
library MerkleProof {
    /**
     * @dev Returns true if a `leaf` can be proved to be a part of a Merkle tree
     * defined by `root`. For this, a `proof` must be provided, containing
     * sibling hashes on the branch from the leaf to the root of the tree. Each
     * pair of leaves and each pair of pre-images are assumed to be sorted.
     */
    function verify(
        bytes32[] memory proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        return processProof(proof, leaf) == root;
    }

    /**
     * @dev Returns the rebuilt hash obtained by traversing a Merklee tree up
     * from `leaf` using `proof`. A `proof` is valid if and only if the rebuilt
     * hash matches the root of the tree. When processing the proof, the pairs
     * of leafs & pre-images are assumed to be sorted.
     *
     * _Available since v4.4._
     */
    function processProof(bytes32[] memory proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                // Hash(current computed hash + current element of the proof)
                computedHash = _efficientHash(computedHash, proofElement);
            } else {
                // Hash(current element of the proof + current computed hash)
                computedHash = _efficientHash(proofElement, computedHash);
            }
        }
        return computedHash;
    }

    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
}
```

**Description:**

The intended behavior of this function is to allow whitelisted users to mint a token by submitting a valid Merkle proof. However, there is a Merkle Proof Replay defect in function mintOG. By replaying a Merkle proof that has already been used, even attackers not on the whitelist can pass the check and mint tokens. Additionally, this function limits each user to minting a maximum of three NFTs. However, by changing the sender of the transaction (msg.sender), users can bypass this check and mint more than three NFTs.

* https://etherscan.io/address/0xe52f3274779d59e98d5876cf24d263cdf1e5c290#code
* https://etherscan.io/address/0x6137cbef171f49c58f92fa696f8fe053688fc93e#code
* https://etherscan.io/address/0xd1ad8ebfb0fb6306962e48260cf1e8062eb28cfa#code

## Case 3

**Contract: https://etherscan.io/address/0xb6cadfb7d4d900f8152954a58bff03901a57c2e2#code**

**Defect:  Weak Randomness from Hashing Chain Attributes**

**Impact: Allow attackers to manipulate the randomness for profit.**

**Defective Functions：**

```solidity
function airdrop()
private
view
returns(bool)
{
    uint256 seed = uint256(keccak256(abi.encodePacked((block.timestamp).add(block.difficulty).add((uint256(keccak256(abi.encodePacked(block.coinbase)))) / (now)).add(block.gaslimit).add((uint256(keccak256(abi.encodePacked(msg.sender)))) / (now)).add(block.number))));
    if((seed - ((seed / 1000) * 1000)) < airDropTracker_)
        return(true);
    else
        return(false);
}

    function core(uint256 _rID, uint256 _pID, uint256 _eth, uint256 _affID, uint256 _team, F3Ddatasets.EventReturns memory _eventData_)
    private
    {
        // if player is new to round
        if (plyrRnds_[_pID][_rID].keys == 0)
            _eventData_ = managePlayer(_pID, _eventData_);

        // early round eth limiter
        if (round_[_rID].eth < 100000000000000000000 && plyrRnds_[_pID][_rID].eth.add(_eth) > 1000000000000000000)
        {
            uint256 _availableLimit = (1000000000000000000).sub(plyrRnds_[_pID][_rID].eth);
            uint256 _refund = _eth.sub(_availableLimit);
            plyr_[_pID].gen = plyr_[_pID].gen.add(_refund);
            _eth = _availableLimit;
        }

        // if eth left is greater than min eth allowed (sorry no pocket lint)
        if (_eth > 1000000000)
        {
            // mint the new keys
            uint256 _keys = (round_[_rID].eth).keysRec(_eth);

            // if they bought at least 1 whole key
            if (_keys >= 1000000000000000000)
            {
                updateTimer(_keys, _rID);

                // set new leaders
                if (round_[_rID].plyr != _pID)
                    round_[_rID].plyr = _pID;
                if (round_[_rID].team != _team)
                    round_[_rID].team = _team;

                // set the new leader bool to true
                _eventData_.compressedData = _eventData_.compressedData + 100;
            }

            // manage airdrops
            if (_eth >= 100000000000000000)
            {
                airDropTracker_++;
                if (airdrop() == true)
                {
                    // gib muni
                    uint256 _prize;
                    if (_eth >= 10000000000000000000)
                    {
                        // calculate prize and give it to winner
                        _prize = ((airDropPot_).mul(75)) / 100;
                        plyr_[_pID].win = (plyr_[_pID].win).add(_prize);

                        // adjust airDropPot
                        airDropPot_ = (airDropPot_).sub(_prize);

                        // let event know a tier 3 prize was won
                        _eventData_.compressedData += 300000000000000000000000000000000;
                    } else if (_eth >= 1000000000000000000 && _eth < 10000000000000000000) {
                        // calculate prize and give it to winner
                        _prize = ((airDropPot_).mul(50)) / 100;
                        plyr_[_pID].win = (plyr_[_pID].win).add(_prize);

                        // adjust airDropPot
                        airDropPot_ = (airDropPot_).sub(_prize);

                        // let event know a tier 2 prize was won
                        _eventData_.compressedData += 200000000000000000000000000000000;
                    } else if (_eth >= 100000000000000000 && _eth < 1000000000000000000) {
                        // calculate prize and give it to winner
                        _prize = ((airDropPot_).mul(25)) / 100;
                        plyr_[_pID].win = (plyr_[_pID].win).add(_prize);

                        // adjust airDropPot
                        airDropPot_ = (airDropPot_).sub(_prize);

                        // let event know a tier 3 prize was won
                        _eventData_.compressedData += 300000000000000000000000000000000;
                    }
                    // set airdrop happened bool to true
                    _eventData_.compressedData += 10000000000000000000000000000000;
                    // let event know how much was won
                    _eventData_.compressedData += _prize * 1000000000000000000000000000000000;

                    // reset air drop tracker
                    airDropTracker_ = 0;
                }
            }

            // store the air drop tracker number (number of buys since last airdrop)
            _eventData_.compressedData = _eventData_.compressedData + (airDropTracker_ * 1000);

            // update player
            plyrRnds_[_pID][_rID].keys = _keys.add(plyrRnds_[_pID][_rID].keys);
            plyrRnds_[_pID][_rID].eth = _eth.add(plyrRnds_[_pID][_rID].eth);

            // update round
            round_[_rID].keys = _keys.add(round_[_rID].keys);
            round_[_rID].eth = _eth.add(round_[_rID].eth);
            rndTmEth_[_rID][_team] = _eth.add(rndTmEth_[_rID][_team]);

            // distribute eth
            _eventData_ = distributeExternal(_rID, _pID, _eth, _affID, _team, _eventData_);
            _eventData_ = distributeInternal(_rID, _pID, _eth, _team, _keys, _eventData_);

            // call end tx function to fire end tx event.
            endTx(_pID, _team, _eth, _keys, _eventData_);
        }
    }
```

**Description:**

This contract implements a game called FoMo3K. During the game, the function airdrop() is called to determine whether the game ends and how rewards are distributed. However, the aridrop function contains the weak randomness from hasing chain attributes defect, which allows attackers to manipulate this random number for profit.



## Case 4

**Contract: 0xfa2dbc4eb68ca6e20be05c8a3d0a6ebeaedc169d**

**Defect:  Cross-Contract Signature Replay**

**Impact: Allow Cross Contract Signature Replay Attack**

**Defective Functions：**

```solidity
    //
    // Verify Approval Digital Signature
    //
    function verifySenderApproved(
        bool isCurator,
        bool oneFree,
        bytes memory signature
    ) private view {
        bytes32 hashedInsideContract = keccak256(
            abi.encodePacked(msg.sender, isCurator, oneFree)
        );
        bytes32 messageDigest = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                hashedInsideContract
            )
        );
        address recovered = ECDSA.recover(messageDigest, signature);
        if (recovered != hugApprovalSigner) revert InvalidApproval();
    }
    
        function mintHUG(
        uint256 count,
        bytes memory signature,
        bool isCurator,
        bool oneFree
    ) public payable {
        unchecked {
            // Verify Minting is Enabled
            if (!mintEnabled) revert MintNotEnabled();

            // Verify Max Mints Not Exceeded
            uint256 mintsUsedCount = _numberMinted(msg.sender);
            uint256 mintsMax = isCurator ? maxMintsCurators : maxMints;
            if ((mintsUsedCount + count) > mintsMax) revert MaxMintsExceeded();

            // Check Total Supply
            if ((totalSupply() + count) > mintMaxSupply)
                revert MintCapacityExceeded();

            // Verify Sufficient ETH
            uint256 ethRequired = calculateEthRequired(
                oneFree,
                mintsUsedCount,
                count
            );
            if (msg.value < ethRequired) revert InsufficientFunds();

            // Verify Digital Signature
            verifySenderApproved(isCurator, oneFree, signature);
            // Mint!
            _safeMint(msg.sender, count);
        }
    }
```

**Description:**

The signature verification logic in this contract has the cross-contract signature replay defect. Specifically, the signed message does not include the current contract's address, allowing the signature to be replayed across different contracts. Notably, we found another contract (https://etherscan.io/tx/0x065f6d5d9b4be74d2d26753761aff3a51ae94dc867f6eb006336b784ca44ba84) on Ethereum that has an identical bytecode to this contract. As a result, signatures for these two contracts are interchangeable, potentially leading to real-world cross-contract signature replay attacks.



## Case 5

**Contract: https://etherscan.io/address/0x0bdDc964f4E8983f6C5e53a3A41C0Ee78c0356ad#code**

**Defect:  Insufficient Signature Verification**

**Impact: Allow Attackers to bypass the signature verification**

**Defective Functions：**

```solidity
/**
 *Submitted for verification at Etherscan.io on 2018-05-28
*/

pragma solidity ^0.4.24;

library DS {
  struct Proof {
    uint level;         // Audit level
    uint insertedBlock; // Audit's block
    bytes32 ipfsHash;   // IPFS dag-cbor proof
    address auditedBy;  // Audited by address
  }
}

contract Audit {
  event AttachedEvidence(address indexed auditorAddr, bytes32 indexed codeHash, bytes32 ipfsHash);
  event NewAudit(address indexed auditorAddr, bytes32 indexed codeHash);

  // Maps auditor address and code's keccak256 to Audit
  mapping (address => mapping (bytes32 => DS.Proof)) public auditedContracts;
  // Maps auditor address to a list of audit code hashes
  mapping (address => bytes32[]) public auditorContracts;
  
  // Returns code audit level, 0 if not present
  function isVerifiedAddress(address _auditorAddr, address _contractAddr) public view returns(uint) {
    bytes32 codeHash = getCodeHash(_contractAddr);
    return auditedContracts[_auditorAddr][codeHash].level;
  }

  function isVerifiedCode(address _auditorAddr, bytes32 _codeHash) public view returns(uint) {
    return auditedContracts[_auditorAddr][_codeHash].level;
  }
  
  function getCodeHash(address _contractAddr) public view returns(bytes32) {
      return keccak256(codeAt(_contractAddr));
  }
  
  // Add audit information
  function addAudit(bytes32 _codeHash, uint _level, bytes32 _ipfsHash) public {
    address auditor = msg.sender;
    require(auditedContracts[auditor][_codeHash].insertedBlock == 0);
    auditedContracts[auditor][_codeHash] = DS.Proof({ 
        level: _level,
        auditedBy: auditor,
        insertedBlock: block.number,
        ipfsHash: _ipfsHash
    });
    auditorContracts[auditor].push(_codeHash);
    emit NewAudit(auditor, _codeHash);
  }
  
  // Add evidence to audited code, only author, if _newLevel is different from original
  // updates the contract's level
  function addEvidence(bytes32 _codeHash, uint _newLevel, bytes32 _ipfsHash) public {
    address auditor = msg.sender;
    require(auditedContracts[auditor][_codeHash].insertedBlock != 0);
    if (auditedContracts[auditor][_codeHash].level != _newLevel)
      auditedContracts[auditor][_codeHash].level = _newLevel;
    emit AttachedEvidence(auditor, _codeHash, _ipfsHash);
  }

  function codeAt(address _addr) public view returns (bytes code) {
    assembly {
      // retrieve the size of the code, this needs assembly
      let size := extcodesize(_addr)
      // allocate output byte array - this could also be done without assembly
      // by using o_code = new bytes(size)
      code := mload(0x40)
      // new "memory end" including padding
      mstore(0x40, add(code, and(add(add(size, 0x20), 0x1f), not(0x1f))))
      // store length in memory
      mstore(code, size)
      // actually retrieve the code, this needs assembly
      extcodecopy(_addr, add(code, 0x20), 0, size)
    }
  }
}

contract MonteLabsMS {
  // MonteLabs owners
  mapping (address => bool) public owners;
  uint8 constant quorum = 2;
  Audit public auditContract;

  constructor(address[] _owners, Audit _auditContract) public {
    auditContract = _auditContract;
    require(_owners.length == 3);
    for (uint i = 0; i < _owners.length; ++i) {
      owners[_owners[i]] = true;
    }
  }

  function addAuditOrEvidence(bool audit, bytes32 _codeHash, uint _level,
                              bytes32 _ipfsHash, uint8 _v, bytes32 _r, 
                              bytes32 _s) internal {
    address sender = msg.sender;
    require(owners[sender]);

    bytes32 prefixedHash = keccak256("\x19Ethereum Signed Message:\n32",
                           keccak256(audit, _codeHash, _level, _ipfsHash));

    address other = ecrecover(prefixedHash, _v, _r, _s);
    // At least 2 different owners
    assert(other != sender);
    if (audit)
      auditContract.addAudit(_codeHash, _level, _ipfsHash);
    else
      auditContract.addEvidence(_codeHash, _level, _ipfsHash);
  }

  function addAudit(bytes32 _codeHash, uint _level, bytes32 _ipfsHash,
                    uint8 _v, bytes32 _r, bytes32 _s) public {
    addAuditOrEvidence(true, _codeHash, _level, _ipfsHash, _v, _r, _s);
  }

  function addEvidence(bytes32 _codeHash, uint _version, bytes32 _ipfsHash,
                    uint8 _v, bytes32 _r, bytes32 _s) public {
    addAuditOrEvidence(false, _codeHash, _version, _ipfsHash, _v, _r, _s);
  }
}
```

**Description:**

The expected behavior of the function `addAuditOrEvidence` is to add an audit report to the blockchain only when it is approved by two auditors. Given a transaction sent by one auditor, the function checks an additional signature from the other auditor to determine if the condition of two auditors' approval is met. However, the signature verification in this function has the insufficient signature verification defect. As a result, even forged signatures can pass the verification of this function, meaning that its signature verification is entirely ineffective.