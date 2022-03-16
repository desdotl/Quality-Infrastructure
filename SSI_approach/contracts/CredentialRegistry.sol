//SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.0;

import "../node_modules/@openzeppelin/contracts/access/AccessControl.sol";
import "./ICredentialRegistry.sol";

contract CredentialRegistry is ICredentialRegistry, AccessControl {
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");
    
    mapping(bytes32 => credentialMetadata) public credentials; //map credential hash to issuer to signer to Credential Metadata
    
    mapping (bytes32 => credentialSubjectMetadata[]) credentialSubjects; // mapping domain to address

    bytes32[] credentialSubjectIDs; 

    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }
   
    function registerCredential(address _issuer,address _signer, address _subject, bytes32 _credentialHash, uint256 _from, uint256 _exp,bytes32 _ipfsHash) external override onlyIssuer returns (bool) {
        
        credentialMetadata storage credential = credentials[_credentialHash];
       
        require(credential.subject == address(0)&& credential.issuer == address(0)&& credential.signer == address(0), "Credential already exists");
        credential.issuer = _issuer;
        credential.signer = _signer;
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
       
        require(credentials[_credentialHash].subject != address(0), "credential hash doesn't exist");
        require(credentials[_credentialHash].status, "Credential is already revoked");
        credentials[_credentialHash].status = false;
        emit CredentialRevoked(_credentialHash, msg.sender, block.timestamp);
        return true;
    }

    function exist(bytes32 _credentialHash) override external view returns (bool){
        
        return (credentials[_credentialHash].subject != address(0) && credentials[_credentialHash].issuer != address(0) && credentials[_credentialHash].signer != address(0));
    }

    function status(bytes32 _credentialHash) override external view returns (bool){
        return credentials[_credentialHash].status;
    }

    function validPeriod(bytes32 _credentialHash) override external view returns (bool){
         return (credentials[_credentialHash].validFrom <= block.timestamp) && (block.timestamp < credentials[_credentialHash].validTo);
    }

    function getSigner(bytes32 _digest, uint8 _v, bytes32 _r, bytes32 _s) external pure returns (address ){
        return ecrecover(_digest, _v, _r, _s);
    }
    function getSigner(bytes32 _digest) external view returns (address issuer){
        return credentials[_digest].signer;
    }
    function getIssuer(bytes32 _digest) external view returns (address issuer){
        return credentials[_digest].issuer;
    }
    function getCredential(bytes32 _credentialHash) external view returns (address ,address , address  , uint256 , uint256 ,bytes32 ) {
        credentialMetadata memory  credential =  credentials[_credentialHash];
        return  (credential.issuer,credential.signer,credential.subject,credential.validFrom,credential.validTo,credential.ipfsHash);
    }

    modifier onlyIssuer() {
        require(hasRole(ISSUER_ROLE, msg.sender), "Caller is not a issuer 2");
        _;
    }

    function registerCredentialSubject(bytes32 credentialSubjectHash, address domainContract,bytes32 domainIpfsHash ) external {
        hasRole(DEFAULT_ADMIN_ROLE,msg.sender);
        if( credentialSubjects[credentialSubjectHash].length==0){
            credentialSubjectIDs.push(credentialSubjectHash);
        }
        credentialSubjects[credentialSubjectHash].push( credentialSubjectMetadata(domainIpfsHash,domainContract,credentialSubjects[credentialSubjectHash].length+1));
    }
    function verifyCredentialSubject(bytes32 credentialSubjectHash, address domainContract , uint version) external view returns (bool){
        return( credentialSubjects[credentialSubjectHash][version-1].domainContract==domainContract);
    }


}