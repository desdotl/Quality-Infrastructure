//SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.0;

interface ICredentialRegistry {

    struct CredentialMetadata {
        address issuer;
        address signer;
        address subject;
        uint256 validFrom;
        uint256 validTo;
        bool status;
        bytes32 ipfsHash;
    }

    function registerCredential(address _issuer,address _signer, address _subject, bytes32 _credentialHash, uint256 _from, uint256 _exp, bytes32 _ipfsHash) external returns (bool);

    function revokeCredential(bytes32 _credentialHash) external returns (bool);

    function exist(bytes32 _credentialHash) external view returns (bool);

    function status(bytes32 _credentialHash) external view returns (bool);

    function validPeriod(bytes32 _credentialHash) external view returns (bool);

    event CredentialRegistered(bytes32 indexed credentialHash, address issuer, address signer, address subject, uint iat, bytes32 _ipfsHash);
    event CredentialRevoked(bytes32 indexed credentialHash, address by, uint256 date);
}