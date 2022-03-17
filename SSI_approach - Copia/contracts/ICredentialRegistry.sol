//SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.0;

interface ICredentialRegistry {

    struct credentialMetadata { 
        
        bytes32 ipfsHash;
        uint64 from;
        uint64 to; 
        bool status;
    }

    struct credentialSubjectMetadata {
        bytes32 domainIpfsHash;
        address domainContract;
        uint64 version;
    }

    function registerCredential( bytes32 _credentialHash, uint64 from, uint64 to, bytes32 _ipfsHash) external;

    function revokeCredential(bytes32 _credentialHash) external;


    event CredentialRegistered(bytes32 indexed credentialHash, uint64 iat);
    event CredentialRevoked(bytes32 indexed credentialHash,  uint64 iat);
}