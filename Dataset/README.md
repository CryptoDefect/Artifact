# Dataset

Specifically, this directory contains the following contents:

* `./contract-list.txt` contains the list of 25,745 Ethereum crypto-related smart contracts. , with each line containing a different contract address.  We collected this dataset to evaluate the effectiveness of CrySol (Section 5).
* `./contracts-statistics.json` contains the statistic of these 25,745 contracts, including the name, transaction count, balance, creation date, and compiler version of these contracts. These statistic information is collected from Etherscan.
* `./SourceCode/` contains the  source codes of these 25,745 smart contracts, with each file containing the source code of one smart contract.
* `./ContractInfo/` contains the ABI information and historical transaction information of these 25,745 smart contracts.
* `./SecurityReports/`contains the security reports collected for defining cryptographic defects.

