//SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.0;

import "./DelegateTypes.sol";

contract  ClaimTypes {

    struct VerifiableCredential {
        address issuer;
        address subject;
        uint256 validFrom;
        uint256 validTo;
        bytes32 data;
    }

    bytes32 constant internal VERIFIABLE_CREDENTIAL_TYPEHASH = keccak256(
            "VerifiableCredential(address issuer,address subject,uint256 validFrom,uint256 validTo,,bytes32 data)"
        );
  

    function hash(VerifiableCredential memory vc) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                VERIFIABLE_CREDENTIAL_TYPEHASH,
                vc.issuer,
                vc.subject,
                vc.validFrom,
                vc.validTo,
                vc.data
            )
        );
    }
   
}