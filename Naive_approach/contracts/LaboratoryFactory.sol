// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./LaboratoryContract.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
    @title LaboratoryFactory
    @notice This contract has the job to instantiate LaboratoryContract. This contract works only after its ownership will be tranfered. Inherits from OpenZeppelin Ownable
    @dev Letting the AuthorityContract create the LaboratoryContract, it would not be deployable due to bytecode too large
 */
contract LaboratoryFactory is Ownable {

    mapping(address => bool) public contracts;

    /**
        @notice Instantiate a contract of type LaboratoryContract with _laboratory as its owner
        @dev This function reverts if ownership has not been tranfered 
        @param _laboratory The owner of the new LaboratoryContract
     */
    function createLaboratoryContract(address _laboratory) onlyOwner public virtual returns(LaboratoryContract) {

        LaboratoryContract c = new LaboratoryContract(_laboratory, msg.sender);
        contracts[address(c)] = true;

        return c;
    }
}

