//SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.0;

import "../node_modules/@openzeppelin/contracts/access/AccessControl.sol";
import "./ICredentialRegistry.sol";

contract CredentialRegistry is ICredentialRegistry, AccessControl {

    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");
    
    mapping( bytes32 => mapping( address => credentialMetadata)) public credentials; //map credential hash to Credential Metadata
    
    mapping (bytes32 => credentialSubjectMetadata[]) credentialSubjects; // mapping domain to address

    bytes32[] credentialSubjectIDs; 

    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }
   
    function registerCredential(bytes32 _credentialHash, uint64 from, uint64 to, bytes32 _ipfsHash) external override onlyIssuer {
       
        require(credentials[_credentialHash][tx.origin].from == 0 , "Credential already exists");
        credentials[_credentialHash][tx.origin].status=true;
        credentials[_credentialHash][tx.origin].from=from;
        credentials[_credentialHash][tx.origin].to=to;
        credentials[_credentialHash][tx.origin].ipfsHash=_ipfsHash;
        emit CredentialRegistered(_credentialHash,uint64(block.timestamp));
        
    }

    function revokeCredential(bytes32 _credentialHash) external override onlyIssuer {

        require(credentials[_credentialHash][tx.origin].from != 0, "Credential doesn't exist");
        require(credentials[_credentialHash][tx.origin].status, "Credential already revoked");
        credentials[_credentialHash][tx.origin].status = false;
        emit CredentialRevoked(_credentialHash, uint64(block.timestamp));
    }

    function getCredentialURI(bytes32 _credentialHash,address _issuer) external view returns (bytes32 ) {
        return credentials[_credentialHash][_issuer].ipfsHash;
    }

    function isActiveCredential(bytes32 _credentialHash,address issuer) external view returns (bool) { 

            return (            credentials[_credentialHash][issuer].from != 0 &&
                                credentials[_credentialHash][issuer].from<uint64(block.timestamp) &&
                                credentials[_credentialHash][issuer].to>uint64(block.timestamp) &&
                                credentials[_credentialHash][issuer].status);
    }

    modifier onlyIssuer() {
        require(msg.sender!=address(0));
        require(hasRole(ISSUER_ROLE, msg.sender), "Caller is not a issuer 2");
        _;
    }

    function registerCredentialSubject(bytes32 credentialSubjectHash, address domainContract,bytes32 domainIpfsHash ) external {
        hasRole(DEFAULT_ADMIN_ROLE,msg.sender);
        if( credentialSubjects[credentialSubjectHash].length==0){
            credentialSubjectIDs.push(credentialSubjectHash);
        }
        credentialSubjects[credentialSubjectHash].push( credentialSubjectMetadata(domainIpfsHash,domainContract,uint64(credentialSubjects[credentialSubjectHash].length+1)));
    }
    function verifyCredentialSubject(bytes32 credentialSubjectHash, address domainContract , uint version) external view returns (bool){
        return( credentialSubjects[credentialSubjectHash][version-1].domainContract==domainContract);
    }


}