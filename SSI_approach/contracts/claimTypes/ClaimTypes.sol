//SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.0;

import "./DelegateTypes.sol";

contract  ClaimTypes is DelegateTypes{

    struct VerifiableCredential {
        address issuer;
        address subject;
        bytes32 data;
        uint256 validFrom;
        uint256 validTo;
    }

    struct DelegatedVerifiableCredential {
        VerifiableDelegate issuer;
        address subject;
        bytes32 data;
        uint256 validFrom;
        uint256 validTo;
    }
    bytes32 constant internal VERIFIABLE_CREDENTIAL_TYPEHASH = keccak256(
            "VerifiableCredential(address issuer,address subject,bytes32 data,uint256 validFrom,uint256 validTo)"
        );
        
    bytes32 constant internal DELEGATED_VERIFIABLE_CREDENTIAL_TYPEHASH = keccak256(
        abi.encodePacked("VerifiableCredential(VerifiableDelegate issuer,address subject,bytes32 data,uint256 validFrom,uint256 validTo)",VERIFIABLE_DELEGATE_TYPEHASH)
    );

   

    function hash(DelegatedVerifiableCredential memory vc) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                DELEGATED_VERIFIABLE_CREDENTIAL_TYPEHASH,
                hash(vc.issuer),
                vc.subject,
                vc.data,
                vc.validFrom,
                vc.validTo
            )
        );
    }

     function hash(VerifiableCredential memory vc) internal pure returns (bytes32) {//0xAABBCC11223344....556677
        return keccak256(
            abi.encode(
                VERIFIABLE_CREDENTIAL_TYPEHASH,
                vc.issuer,
                vc.subject,
                vc.data,
                vc.validFrom,
                vc.validTo
            )
        );
    }

   
}