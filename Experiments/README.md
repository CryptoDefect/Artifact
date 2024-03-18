# Experiment

This directory contains the results of the experiment in our paper (Section 5). Specifically, it contains the following files:

* `./contract-list.txt` contains 25,745 smart contracts used in the experiment.
* `./rawResult.out` stores the raw results outputted by CrySol during the experiment.
* ``./Dataset1/``  is a directory containing all datasets used in Section 5.2. It includes nine `.csv` files named by nine types of defects. Each file contains a list of contracts that reported to have that defects. For example, the `./Dataset1/Single_Contract_Signature_Replay.csv` file contains 59 contracts. The first column in this file is the contract address reported by CrySol to have the single-contract-signature-replay defect, while the second column is "TP" (True Positive) or "FP" (False Positive), representing the manual labeling results that verify whether the defect reported by CrySol is a true positive or a false positive.
* ``./Dataset2/ `` contains the manually annotated dataset  in Section 5.3. The ``./Dataset2/Dataset2.csv`` file includes 96 smart contracts. Each row represents a contract, and each column represents a type of defect. The meaning of each cell is whether CrySol's analysis result for the contract in that row and the defect in that column is a "TP" (True Positive) or "FP" (False Positive) or "TN" (True Negative) or "FN" (False Negative) .
* `./Case.md` studies several defective cases reported by CrySol.
* `./Mitigation.md` provides possible protective solutions for cryptographic defects, as well as examples to apply them.



### Reproduce the Experiment Results

The following commands can be used to reproduce the experiment results in our paper. They will analyze 25,745 contracts listed in  `Dataset/contract-list.txt` and output analysis result.

```sh
cd CrySol
make all
.build/bin/crysol fuzz-batch --substatedir=/path/to/substatedir/  --contract-info=../Dataset/ContractInfo/ --contract-list=../Dataset/contract-list.txt
```

The file `Experiments/rawResult.out` stores the raw results from executing these commands.

For more details about how to run CrySol, please refer to `CrySol/README.md`.