//SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.0;

contract ClaimTypes {

  struct Delegate {
    uint64 validFrom;
    uint64 validTo;
    bytes32 allwedTypeHash;
    uint64 version; 
    address issuer;
    address subject;
  }

  struct VerifiableCredential {
      uint64 validFrom;
      uint64 validTo;
      bytes32 data;
      bytes32 typeHash;
      uint64 version;
      address issuer;
      address subject;
  }

  bytes32 constant DELEGATE_TYPEHASH = keccak256(
    "Delegate(uint64 validFrom,uint64 validTo,bytes32 allwedTypeHash,uint64 version,address issuer,address subject)"
  );

  bytes32 constant internal VERIFIABLE_CREDENTIAL_TYPEHASH = keccak256(
        abi.encodePacked("VerifiableCredential(uint64 validFrom,uint64 validTo,bytes32 data,bytes32 typeHash,uint64 version,address issuer,address subject)")
    );

  function hash(Delegate memory delegate) public pure returns (bytes32) {
    return keccak256(
      abi.encode(
        DELEGATE_TYPEHASH,
        delegate.validFrom,
        delegate.validTo,
        delegate.allwedTypeHash,
        delegate.version,
        delegate.issuer,
        delegate.subject
      )
    );
  }

    function hash(VerifiableCredential memory vc) public pure returns (bytes32) {
    return keccak256(
      abi.encode(
        VERIFIABLE_CREDENTIAL_TYPEHASH,
        vc.validFrom,
        vc.validTo,
        vc.typeHash,
        vc.version,
        vc.data,
        vc.issuer,
        vc.subject
      )
    );
  }
}

