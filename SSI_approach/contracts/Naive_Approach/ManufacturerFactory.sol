// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./ManufacturerContract.sol";
import "../../node_modules/@openzeppelin/contracts/access/Ownable.sol";

/**
    @title ManufacturerFactory
    @notice This contract has the job to instantiate ManufacturerContract. This contract works only after its ownership will be tranfered. Inherits from OpenZeppelin Ownable
    @dev Letting the AuthorityContract create the ManufacturerContract, it would not be deployable due to bytecode too large
 */
contract ManufacturerFactory is Ownable {

    mapping(address => bool) public contracts;

    /**
        @notice Instantiate a contract of type ManufacturerContract with _manufacturer as its owner
        @dev This function reverts if ownership has not been tranfered 
        @param _manufacturer The owner of the new ManufacturerContract
     */
    function createManufacturerContract(address _manufacturer) onlyOwner public virtual returns(ManufacturerContract) {

        ManufacturerContract c = new ManufacturerContract(_manufacturer, msg.sender);
        contracts[address(c)] = true;

        return c;
    }
}

