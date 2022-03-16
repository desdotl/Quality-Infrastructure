//SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.0;

import "./CredentialRegistry.sol";
import "./EthereumDIDRegistry.sol";
import "./lib/ECDSA.sol";


contract AbstractClaimsVerifier {

    using ECDSA for bytes32;

    CredentialRegistry registry;
    EthereumDIDRegistry DIDregistry;

    struct EIP712Domain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }

    bytes32 constant EIP712DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 DOMAIN_SEPARATOR;

    constructor (
        string memory name,
        string memory version,
        uint256 chainId,
        address verifyingContract,
        address _registryAddress,
        address _DIDregistryAddress) {
        DOMAIN_SEPARATOR = hashEIP712Domain(
            EIP712Domain({
        name : name,
        version : version,
        chainId : chainId,
        verifyingContract : verifyingContract
        }));
        registry = CredentialRegistry(_registryAddress);
        DIDregistry = EthereumDIDRegistry(_DIDregistryAddress);
    }

    function hashEIP712Domain(EIP712Domain memory eip712Domain) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712DOMAIN_TYPEHASH,
                keccak256(bytes(eip712Domain.name)),
                keccak256(bytes(eip712Domain.version)),
                eip712Domain.chainId,
                eip712Domain.verifyingContract
            )
        );
    }

    function _registerCredential(address _sender,address _issuer,address _signer, address _subject, bytes32 _credentialHash, uint256 _from, uint256 _exp, bytes32 _ipfsHash,bytes memory _signature) internal returns (bool){
        require(_sender== _credentialHash.recover(_signature),"Signature not corresponding");
        if (_signer!=_issuer){
            if(!DIDregistry.validDelegate(_issuer, "veriKey",_signer ))
                return false;
        }
        return registry.registerCredential(_issuer,_signer, _subject, _credentialHash, _from, _exp, _ipfsHash);
    }

    function _validPeriod(uint256 _validFrom, uint256 _validTo) internal view returns (bool) {
        return (_validFrom <= block.timestamp) && (block.timestamp < _validTo);
    }

    function _validPeriod(bytes32 _credentialHash) internal view returns (bool) {
        return registry.validPeriod(_credentialHash);
    }

    function _verifySigner(bytes32 _digest, address _signer, uint8 _v, bytes32 _r, bytes32 _s) internal pure returns (bool) {
        return (_signer == ecrecover(_digest, _v, _r, _s));
    }
    function _verifySigner(bytes32 _digest, address _signer, bytes memory _signature) internal pure returns (bool) {
        return (_signer == _digest.recover(_signature));
    }
    function _verifyDelegation(bytes32 _digest, address _issuer, bytes memory _signature)internal view returns (bool) {
        return DIDregistry.validDelegate(_issuer, "veriKey", _digest.recover(_signature));
    }
    function _verifyDelegation(bytes32 _digest, address _issuer, uint8 _v, bytes32 _r, bytes32 _s)internal view returns (bool) {
        return DIDregistry.validDelegate(_issuer, "veriKey", ecrecover(_digest, _v, _r, _s));
    }

    function _exist(bytes32 _credentialHash) internal view returns (bool){
        return registry.exist(_credentialHash);
    }

    function _Revoked(bytes32 _credentialHash) internal view returns (bool){
        return !registry.status(_credentialHash);
    }

    function _isActiveCredential(bytes32 _credentialHash) internal view returns (bool) { 
            return (_exist(_credentialHash) && !_Revoked(_credentialHash) && _validPeriod(_credentialHash));
    }
    function _domainHash(bytes32 _hash) internal view returns (bytes32){
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                _hash
            )
        ); 
    }

}
