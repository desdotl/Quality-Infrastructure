// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./AccreditorContract.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
    @title AccreditorFactory
    @notice This contract has the job to instantiate AccreditorContract. This contract works only after its ownership will be tranfered. Inherits from OpenZeppelin Ownable
    @dev Letting the AuthorityContract create the AccreditorContract, it would not be deployable due to bytecode too large
 */
contract AccreditorFactory is Ownable {

    mapping(address => bool) public contracts;

    /**
        @notice Instantiate a contract of type AccreditorContract with _accreditor as its owner
        @dev This function reverts if ownership has not been tranfered 
        @param _accreditor The owner of the new AccreditorContract
     */
    function createAccreditorContract(address _accreditor) onlyOwner public virtual returns(AccreditorContract) {

        AccreditorContract c = new AccreditorContract(_accreditor, msg.sender);
        contracts[address(c)] = true;

        return c;
    }
}

