// SPDX-License-Identifier: MIT
pragma solidity 0.8.14;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import "./interfaces/ICryptoPunksMarket.sol";
import "./LendingCore.sol";

error InvalidSender();
error UnknownTokenType();

/// @notice liqd lending and borrowing contract
contract LiqdLending is
    ReentrancyGuard,
    ERC721Holder,
    ERC1155Holder,
    LendingCore
{
    using SafeERC20 for IERC20;

    address private constant ETH_ADDRESS =
        0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    address public DAO; // solhint-disable-line var-name-mixedcase
    uint256 public id;
    bool public onlyExitLoan;
    mapping(bytes => bool) public cancelledSignatures;
    uint256 internal durationUnit = 86400; // Unit: 1 day
    bool internal canChangeDurationUnit;
    mapping(bytes => bool) internal usedSignatures;

    constructor(
        address _DAO, // solhint-disable-line var-name-mixedcase
        bool _canChangeDurationUnit
    ) {
        require(_DAO != address(0), "ZERO_ADDRESS");
        DAO = _DAO;
        canChangeDurationUnit = _canChangeDurationUnit;
    }

    /// @notice Borrowers transfer their nft as collateral to Vault and get paid from the lenders.
    /// @param _payload structure LoanPayload
    /// @param _sig user's signed message
    /// @return currentId id of the created loan
    function createLoan(LoanPayload memory _payload, bytes memory _sig)
        external
        payable
        nonReentrant
        returns (uint256 currentId)
    {
        require(!usedSignatures[_sig], "This signature is already used");
        require(!cancelledSignatures[_sig], "This signature is not valid");

        bytes32 _payloadHash = keccak256(
            abi.encode(
                _payload.borrower,
                _payload.nftAddress,
                _payload.currency,
                _payload.nftTokenId,
                _payload.duration,
                _payload.expiration,
                _payload.loanAmount,
                _payload.apr,
                _payload.nftTokenType
            )
        );

        bytes32 messageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", _payloadHash)
        );
        if (msg.sender == _payload.borrower) {
            require(
                ECDSA.recover(messageHash, _sig) == _payload.lender,
                "INVALID_SIGNATURE_LENDER"
            );
        } else if (msg.sender == _payload.lender) {
            require(
                ECDSA.recover(messageHash, _sig) == _payload.borrower,
                "INVALID_SIGNATURE_BORROWER"
            );
        } else {
            revert InvalidSender();
        }

        currentId = _createLoan(_payload);
        usedSignatures[_sig] = true;
    }

    /// @notice Borrowers transfer their nft as collateral to Vault and get paid from the lenders.
    /// @param _payload structure LoanPayload
    /// @param _sig lender's signed message
    /// @return currentId id of the created loan
    function createCOffer(LoanPayload memory _payload, bytes memory _sig)
        external
        payable
        nonReentrant
        returns (uint256 currentId)
    {
        require(!usedSignatures[_sig], "This signature is already used");
        require(!cancelledSignatures[_sig], "This signature is not valid");
        require(msg.sender == _payload.borrower, "The caller is not borrower");

        bytes32 _payloadHash = keccak256(
            abi.encode(
                _payload.lender,
                _payload.nftAddress,
                _payload.currency,
                _payload.duration,
                _payload.expiration,
                _payload.loanAmount,
                _payload.apr,
                _payload.nftTokenType
            )
        );

        bytes32 messageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", _payloadHash)
        );
        require(
            ECDSA.recover(messageHash, _sig) == _payload.lender,
            "INVALID_SIGNATURE"
        );

        currentId = _createLoan(_payload);
        usedSignatures[_sig] = true;
    }

    /// @notice internal function to create loan
    /// @param _payload structure LoanPayload
    /// @return currentId id of the created loan
    function _createLoan(LoanPayload memory _payload)
        internal
        returns (uint256 currentId)
    {
        require(!onlyExitLoan, "ONLY_EXIT_LOAN");
        require(_payload.expiration >= block.timestamp, "EXPIRED_SIGNATURE"); // solhint-disable-line not-rely-on-time
        require(availableCurrencies[_payload.currency], "NOT_ALLOWED_CURRENCY");
        require(_payload.duration > 0, "ZERO_DURATION");

        uint256 platformFee = calculatePlatformFee(
            _payload.loanAmount,
            platformFees[_payload.currency]
        );

        currentId = id;
        loans[currentId] = Loan({
            nftAddress: _payload.nftAddress,
            nftTokenId: _payload.nftTokenId,
            startTime: block.timestamp, // solhint-disable-line not-rely-on-time
            endTime: block.timestamp + (_payload.duration * durationUnit), // solhint-disable-line not-rely-on-time
            currency: _payload.currency,
            loanAmount: _payload.loanAmount,
            amountDue: calculateDueAmount(
                _payload.loanAmount,
                _payload.apr,
                _payload.duration
            ),
            status: Status.CREATED,
            borrower: _payload.borrower,
            lender: _payload.lender,
            nftTokenType: _payload.nftTokenType
        });

        transferNFT(
            _payload.borrower,
            address(this),
            _payload.nftAddress,
            _payload.nftTokenId,
            _payload.nftTokenType,
            false
        );

        if (_payload.currency != ETH_ADDRESS) {
            IERC20(_payload.currency).safeTransferFrom(
                _payload.lender,
                _payload.borrower,
                _payload.loanAmount - platformFee
            );
            if (platformFee > 0) {
                IERC20(_payload.currency).safeTransferFrom(
                    _payload.lender,
                    DAO,
                    platformFee
                );
            }
        } else {
            require(
                msg.value >= _payload.loanAmount + platformFee,
                "ETH value is not enough."
            );
            (bool toSuccess, ) = _payload.borrower.call{ // solhint-disable-line avoid-low-level-calls
                value: _payload.loanAmount - platformFee
            }("");
            require(toSuccess, "Transfer failed");
            if (platformFee > 0) {
                (bool daoSuccess, ) = DAO.call{value: platformFee}(""); // solhint-disable-line avoid-low-level-calls
                require(daoSuccess, "Transfer failed to DAO");
            }
        }

        emit LoanCreated(
            _payload.lender,
            _payload.borrower,
            _payload.nftAddress,
            _payload.nftTokenId,
            currentId,
            _payload.currency,
            _payload.loanAmount,
            platformFee
        );

        ++id;
    }

    /// @notice Borrower pays back for loan
    /// @param _loanId the id of loans
    /// @param _amountDue amount is needed to pay
    function repayLoan(uint256 _loanId, uint256 _amountDue)
        external
        payable
        nonReentrant
    {
        Loan storage loan = loans[_loanId];
        address loanCurrency = loan.currency;
        require(loan.borrower == msg.sender, "WRONG_MSG_SENDER");
        require(loan.status == Status.CREATED, "NOT_LOAN_CREATED");
        require(block.timestamp <= loan.endTime, "EXPIRED_LOAN"); // solhint-disable-line not-rely-on-time
        require(
            (msg.value > 0 &&
                loanCurrency == address(0) &&
                msg.value >= _amountDue &&
                _amountDue >= loan.amountDue) ||
                (loanCurrency != address(0) &&
                    msg.value == 0 &&
                    _amountDue >= loan.amountDue),
            "Pay back amount is not enough."
        );

        loan.status = Status.REPAID;

        transferNFT(
            address(this),
            loan.borrower,
            loan.nftAddress,
            loan.nftTokenId,
            loan.nftTokenType,
            true
        );
        if (loan.currency != ETH_ADDRESS) {
            IERC20(loan.currency).safeTransferFrom(
                msg.sender,
                loan.lender,
                _amountDue
            );
        } else {
            require(msg.value >= _amountDue, "ETH value is not enough.");
            (bool toSuccess, ) = loan.lender.call{value: _amountDue}(""); // solhint-disable-line avoid-low-level-calls
            require(toSuccess, "Transfer failed");
            if (msg.value > _amountDue) {
                (bool retSuccess, ) = payable(msg.sender).call{ // solhint-disable-line avoid-low-level-calls
                    value: msg.value - _amountDue
                }("");
                require(retSuccess, "Transfer back failed");
            }
        }

        emit LoanLiquidated(
            loan.lender,
            loan.borrower,
            loan.nftAddress,
            loan.nftTokenId,
            _loanId
        );
    }

    /// @notice Lender can liquidate loan item if loan is not paid
    /// @param _loanId the id of loans
    function liquidateLoan(uint256 _loanId) external nonReentrant {
        Loan storage loan = loans[_loanId];
        require(loan.status == Status.CREATED, "LOAN_FINISHED");
        require(block.timestamp >= loan.endTime, "NOT_EXPIRED_LOAN"); // solhint-disable-line not-rely-on-time

        loan.status = Status.LIQUIDATED;
        transferNFT(
            address(this),
            loan.lender,
            loan.nftAddress,
            loan.nftTokenId,
            loan.nftTokenType,
            true
        );

        emit LoanTerminated(
            loan.lender,
            loan.borrower,
            loan.nftAddress,
            loan.nftTokenId,
            _loanId
        );
    }

    /// @notice Set onlyExistLoan by owner
    /// @param _value value
    function setOnlyExitLoan(bool _value) external onlyOwner {
        onlyExitLoan = _value;
    }

    /// @notice Set cancelled signatures by client
    /// @param _sig user's signed message
    /// @return status result of this function
    function setCancelledSignature(bytes memory _sig) external returns (bool) {
        cancelledSignatures[_sig] = true;
        return true;
    }

    /// @notice Change durationUnit by owner
    /// @param _value value
    function changeDurationUnit(uint256 _value) external onlyOwner {
        require(canChangeDurationUnit, "NOT_CHANGE_DURATION_UNIT");
        durationUnit = _value;
    }

    /// @notice Standard method to send nft from an account to another
    function transferNFT(
        address _from,
        address _to,
        address _nftAddress,
        uint256 _nftTokenId,
        uint8 _nftTokenType,
        bool _punkTransfer
    ) internal {
        if (_nftTokenType == 0) {
            IERC721(_nftAddress).safeTransferFrom(_from, _to, _nftTokenId);
        } else if (_nftTokenType == 1) {
            IERC1155(_nftAddress).safeTransferFrom(
                _from,
                _to,
                _nftTokenId,
                1,
                "0x00"
            );
        } else if (_nftTokenType == 2) {
            if (_punkTransfer) {
                ICryptoPunksMarket(_nftAddress).transferPunk(_to, _nftTokenId);
            } else {
                ICryptoPunksMarket(_nftAddress).buyPunk(_nftTokenId);
            }
        } else {
            revert UnknownTokenType();
        }
    }
}