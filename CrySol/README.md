# CrySol



## Description

This directory contains CrySol's source code, a fuzzing-based tool designed to detect cryptographic defects in Ethereum smart contracts.



## Installation

**Environment: CrySol is tested on Go v1.19, and Ubuntu 22.04.2 LTS.**

**Installation steps for CrySol:**

```sh
cd CrySol
make all
```



## Usage

### Initialization

To access historical contracts' states and transactions, CrySol requires an archive node of Ethereum on the mainnet. Please follow the official instructions of [Geth + Prysm](https://docs.prylabs.network/docs/install/install-with-script#introduction) to sync the blockchain. After the synchronization is complete, run the following command to export the blockchain states to a binary format file.

```sh
geth export /path/to/blockfile/
```

Then, execute the following commands to let CrySol import the binary file and record blockchain states. CrySol employs [record-replay](https://github.com/verovm/record-replay/blob/master/research/README.md#record-transaction-substates) for splitting the entire block state file into contract substates, which are then used in the fuzzing process.

```sh
cd CrySol
make all
./build/bin/geth import /path/to/blockfile/ --substatedir=/path/to/substatedir/
```



### Fuzz Smart Contracts

Once initialization is complete, CrySol is ready to fuzz smart contracts.

For detailed usage information, execute the help command below:

```sh
cd CrySol
make all
./buid/bin/crysol --help
```

```
NAME:
   crysol - CrySol command line interface

USAGE:
   crysol [global options] command [command options] [arguments...]

VERSION:
   1.10.15-stable

COMMANDS:
     fuzz        fuzz the input contract and output the detected defects
     fuzz-batch  fuzz a batch of contracts and output the detected defects.
     help, h     Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help
   --version, -v  print the version
```



#### Fuzz a smart contract

To fuzz a specific contract, please use the `./crysol fuzz` command. This command requires the following options:

```
fuzz [command options]
fuzz the input contract and output the detected defects

OPTIONS:
   --substatedir value    Data directory for substate recorder (default: "substate.ethereum")
   --addr value           The mainnet address of the contract to analyze
   --contract-info value  The directory that stores the ABI information and historical transactions of the contract
   --detail-report        Output the detailed report of the defect, including the attack transaction sequences.
   --max-txns value       Number of historical txns to fetch. (default: 500)

```



**Example:**  Run the following command to analyze the contract 0x11606995338D83aCAbCD06BaBaf4Cdad66C73140. Specifically, `/path/to/substatedir/` is the directory used to store the substates during the initialization. `/path/to/Dataset/ContractInfo/` is the path of `Dataset/ContractInfo` directory in this online supplement material.

```BASH
./crysol fuzz --addr=0xfD217296e581627C59e3a36c264eBfbCbd813223 --substatedir=/path/to/substatedir/ --contract-info=/path/to/Dataset/ContractInfo/
```

It will take several seconds for the results to appear in the console. The expected output is as follows, indicating that the function with selector `0xe6a1871a` in contract 0xfD217296e581627C59e3a36c264eBfbCbd813223 has a Cross-Contract Signature Replay defect.

```
Contract:0xfD217296e581627C59e3a36c264eBfbCbd813223, Result: map[0xe6a1871a:[Cross-Contract Signature Replay;]]
```



#### Fuzz smart contracts in batch

The`./crysol fuzz-batch ` command conducts the fuzzing process for a given contract. Specifically, it requires the following options.

```
fuzz-batch [command options] 
fuzz a batch of contracts and output the detected defects.

OPTIONS:
   --contract-list value  A file containting the list of contract addresses to analyze. Each line is a contract address.
   --substatedir value    Data directory for substate recorder (default: "substate.ethereum")
   --contract-info value  The directory that stores the ABI information and historical transactions of the contract
   --detail-report        Output the detailed report of the defect, including the attack transaction sequences.
   --max-txns value       Number of historical txns to fetch. (default: 500)
```



**Example:** Execute the command below for batch analysis of contracts. Here,  `/path/to/substatedir/` is the directory used to store the substates during the initialization. `/path/to/Dataset/ContractInfo/` is the path of `Dataset/ContractInfo` directory in this online supplement material. `/path/to/contractlist/`is the file containing a list of contract addresses to analyze, with each line representing a different address.

```
./crysol fuzz-batch --substatedir=/path/to/substatedir/ --contract-info=/path/to/Dataset/ContractInfo/ --contract-list=/path/to/contractlist/
```



### Reproduce the Experiment Results

The following commands can be used to reproduce the experiment results in out paper. They will analyze 25,745 contracts listed in  `Dataset/contract-list.txt` and output analysis result.

```sh
cd CrySol
make all
.build/bin/crysol fuzz-batch --substatedir=/path/to/substatedir/  --contract-info=../Dataset/ContractInfo/ --contract-list=../Dataset/contract-list.txt
```

The file `Experiments/rawResult.out` stores the raw results from executing these commands.

