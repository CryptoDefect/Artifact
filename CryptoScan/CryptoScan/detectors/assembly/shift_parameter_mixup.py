from typing import List
from CryptoScan.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from CryptoScan.slithir.operations import Binary, BinaryType
from CryptoScan.slithir.variables import Constant
from CryptoScan.core.declarations.function_contract import FunctionContract
from CryptoScan.utils.output import Output
from CryptoScan.core.cfg.node import NodeType


class ShiftParameterMixup(AbstractDetector):
    """
    Check for cases where a return(a,b) is used in an assembly function that also returns two variables
    """

    ARGUMENT = "incorrect-shift"
    HELP = "The order of parameters in a shift instruction is incorrect."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = (
        "https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-shift-in-assembly"
    )

    WIKI_TITLE = "Incorrect shift in assembly."
    WIKI_DESCRIPTION = "Detect if the values in a shift operation are reversed"

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract C {
    function f() internal returns (uint a) {
        assembly {
            a := shr(a, 8)
        }
    }
}
```
The shift statement will right-shift the constant 8 by `a` bits"""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Swap the order of parameters."

    def _check_function(self, f: FunctionContract) -> List[Output]:
        results = []
        in_assembly = False

        for node in f.nodes:
            if node.type == NodeType.ASSEMBLY:
                in_assembly = True
                continue
            if node.type == NodeType.ENDASSEMBLY:
                in_assembly = False
                continue
            if not in_assembly:
                continue

            for ir in node.irs:
                if isinstance(ir, Binary) and ir.type in [
                    BinaryType.LEFT_SHIFT,
                    BinaryType.RIGHT_SHIFT,
                ]:
                    if isinstance(ir.variable_left, Constant) and not isinstance(
                        ir.variable_right, Constant
                    ):
                        info: DETECTOR_INFO = [
                            f,
                            " contains an incorrect shift operation: ",
                            node,
                            "\n",
                        ]
                        json = self.generate_result(info)

                        results.append(json)
        return results

    def _detect(self) -> List[Output]:
        results = []
        for c in self.contracts:
            for f in c.functions:
                if f.contract_declarer != c:
                    continue

                if f.contains_assembly:
                    results += self._check_function(f)

        return results
