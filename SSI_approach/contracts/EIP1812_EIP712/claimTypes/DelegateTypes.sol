//SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.0;

contract DelegateTypes {

  struct Delegate {
    address issuer;
    address subject;
    bytes32 allwedTypeHash;
    uint version;
    uint256 validFrom;
    uint256 validTo;
  }

  struct VerifiableDelegate {
    Delegate delegate;
    uint8 v;
    bytes32 r;
    bytes32 s;
  }

   struct DelegatedVerifiableCredential {
        VerifiableDelegate issuer;
        address subject;
        uint256 validFrom;
        uint256 validTo;
        bytes32 data;
    }

    

  bytes32 constant DELEGATE_TYPEHASH = keccak256(
    "Delegate(address issuer, address subject, bytes32 allwedTypeHash, uint version, uint256 validFrom, uint256 validTo)"
  );

  bytes32 constant VERIFIABLE_DELEGATE_TYPEHASH = keccak256(
    abi.encodePacked("VerifiableDelegate(Delegate delegate, uint8 v, bytes32 r, bytes32 s)", DELEGATE_TYPEHASH)
  );

  bytes32 constant internal DELEGATED_VERIFIABLE_CREDENTIAL_TYPEHASH = keccak256(
        abi.encodePacked("VerifiableCredential(VerifiableDelegate issuer,address subject,uint256 validFrom,uint256 validTo,bytes32 data)",VERIFIABLE_DELEGATE_TYPEHASH)
    );

  function hash(Delegate memory delegate) public pure returns (bytes32) {
    return keccak256(
      abi.encode(
        DELEGATE_TYPEHASH,
        delegate.issuer,
        delegate.subject,
        delegate.allwedTypeHash,
        delegate.version,
        delegate.validFrom,
        delegate.validTo
      )
    );
  }

  function hash(VerifiableDelegate memory verified) public pure returns (bytes32) {
    return keccak256(
      abi.encode(
        VERIFIABLE_DELEGATE_TYPEHASH,
        hash(verified.delegate),
        verified.v,
        verified.r,
        verified.s
      )
    );
  }

  function hash(DelegatedVerifiableCredential memory vc) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                DELEGATED_VERIFIABLE_CREDENTIAL_TYPEHASH,
                hash(vc.issuer),
                vc.subject,
                vc.validFrom,
                vc.validTo,
                vc.data
            )
        );
    }

}

