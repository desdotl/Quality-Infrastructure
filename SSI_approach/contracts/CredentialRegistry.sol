//SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.0;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./ICredentialRegistry.sol";

contract CredentialRegistry is ICredentialRegistry, AccessControl {
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");
    
    mapping(bytes32 => CredentialMetadata) public credentials; //map credential hash to issuer to signer to Credential Metadata

    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }
   
    function registerCredential(address _issuer,address _signer, address _subject, bytes32 _credentialHash, uint256 _from, uint256 _exp,bytes32 _ipfsHash) external override onlyIssuer returns (bool) {
        
        CredentialMetadata storage credential = credentials[_credentialHash];
       
        require(credential.subject == address(0)&& credential.issurer == address(0)&& credential.signer == address(0), "Credential already exists");
        credential.subject = _issuer;
        credential.subject = _signer;
        credential.subject = _subject;
        credential.validFrom = _from;
        credential.validTo = _exp;
        credential.status = true;
        credential.ipfsHash= _ipfsHash;
        credentials[_credentialHash] = credential;
        emit CredentialRegistered(_credentialHash, _issuer, _signer, _subject, credential.validFrom, credential.ipfsHash);
        return true;
    }

    function revokeCredential(bytes32 _credentialHash) external override returns (bool) {
        
        require(credential.subject != address(0), "credential hash doesn't exist");
        require(credential.status, "Credential is already revoked");
        credentials[_credentialHash].status = false;
        emit CredentialRevoked(_credentialHash, msg.sender, block.timestamp);
        return true;
    }

    function exist(bytes32 _credentialHash) override external view returns (bool){
        
        return (credential.subject != address(0) && credential.issurer != address(0) && credential.signer != address(0));
    }

    function status(bytes32 _credentialHash) override external view returns (bool){
        return credentials[_credentialHash].status;
    }

    function getSigner(bytes32 _digest, uint8 _v, bytes32 _r, bytes32 _s) external pure returns (address issuer){
        return ecrecover(_digest, _v, _r, _s);
    }

    function getCredential(bytes32 _credentialHash) external view returns (CredentialMetadata calldata) {
        return  credentials[_credentialHash];
    }

    modifier onlyIssuer() {
        require(hasRole(ISSUER_ROLE, msg.sender), "Caller is not a issuer 2");
        _;
    }

}