//SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.0;

import "./ClaimsVerifier.sol";

contract AuthorityContract is ClaimsVerifier {

    bytes32 ID_TYPEHASH;
    bytes32 DSOA_TYPEHASH;
    bytes32 DEVID_TYPEHASH;
    bytes32 DCC_TYPEHASH;
    bytes32 ACCREDITATION_TYPEHASH; // Accreditor can register new Issuer for ID, DSOA, DEV_ID
    
    constructor(bytes32 _ID_TYPEHASH,
    bytes32 _ID_TYPEHASH_IPFS,
    bytes32 _DSOA_TYPEHASH,
    bytes32 _DSOA_TYPEHASHIPFS,
    bytes32 _DEVID_TYPEHASH,
    bytes32 _DEVID_TYPEHASH_IPFS,
    bytes32 _DCC_TYPEHASH,
    bytes32 _DCC_TYPEHASH_IPFS,
    bytes32 _ACCREDITATION_TYPEHASH,
    bytes32 _ACCREDITATION_TYPEHASH_IPFS,
    address _registryAddress,
    address _DIDregistryAddress
    ) 
    ClaimsVerifier( _registryAddress,  _DIDregistryAddress){
        
        // register credentialSubject for the relevant credential 

            registry.registerCredentialSubject(_ID_TYPEHASH, address(this), _ID_TYPEHASH_IPFS);
            registry.registerCredentialSubject(_DSOA_TYPEHASH, address(this),_DSOA_TYPEHASHIPFS);
            registry.registerCredentialSubject(_DEVID_TYPEHASH, address(this),_DEVID_TYPEHASH_IPFS);
            registry.registerCredentialSubject(_DCC_TYPEHASH, address(this),_DCC_TYPEHASH_IPFS);
            registry.registerCredentialSubject(_ACCREDITATION_TYPEHASH, address(this),_ACCREDITATION_TYPEHASH_IPFS);
            
            ACCREDITATION_TYPEHASH=_ACCREDITATION_TYPEHASH;
            DSOA_TYPEHASH=_DSOA_TYPEHASH;
            DEVID_TYPEHASH=_DEVID_TYPEHASH;
            DCC_TYPEHASH=_DCC_TYPEHASH;
            ID_TYPEHASH=_ID_TYPEHASH;
        
    }

    function registerAccreditorIssuer(VerifiableCredential memory vc, bytes32 _ipfsHash,bytes memory _signature) external returns (bool){   

        require(hasRole(DEFAULT_ADMIN_ROLE,msg.sender));
        require(vc.allwedTypeHash==ACCREDITATION_TYPEHASH);
        issuers[vc.subject]=IssuerMeta( registerCredential(vc, _ipfsHash, _signature),ACCREDITATION_TYPEHASH);
        grantRole(ISSUER_ROLE, vc.subject);
        return true;
    }

    function registerIDIssuer(VerifiableCredential memory vc, bytes32 _ipfsHash,bytes memory _signature) external onlyIssuer returns (bool)  {

        require( issuers[msg.sender].allwedTypeHash==ACCREDITATION_TYPEHASH, "Only Accreditor can accredit IDIssuer");
        require(vc.allwedTypeHash==ACCREDITATION_TYPEHASH);
        issuers[vc.subject]=IssuerMeta( registerCredential(vc, _ipfsHash, _signature),ID_TYPEHASH);
        grantRole(ISSUER_ROLE, vc.subject);
        return true;
    }

    function registerIDCredential(DelegatedVerifiableCredential memory vc, bytes32 _ipfsHash,bytes memory _signature) external returns (bytes32){
        return registerCredential(vc,_ipfsHash,_signature);
    }

    function registerDEVIDIssuer(VerifiableCredential memory vc, bytes32 _ipfsHash,bytes memory _signature) onlyIssuer external returns (bool){
        require( issuers[msg.sender].allwedTypeHash==ACCREDITATION_TYPEHASH, "Only Accreditor can accredit DEVIDIssuer");
        require(vc.allwedTypeHash==ACCREDITATION_TYPEHASH);
        issuers[vc.subject]=IssuerMeta( registerCredential(vc, _ipfsHash, _signature),DEVID_TYPEHASH);
        grantRole(ISSUER_ROLE, vc.subject);
        return true;
    }

    function registerDEVIDCredential(DelegatedVerifiableCredential memory vc, bytes32 _ipfsHash,bytes memory _signature) external returns (bytes32){
        return registerCredential(vc,_ipfsHash,_signature);
    }

    function registerDSOAIssuer(VerifiableCredential memory vc, bytes32 _ipfsHash,bytes memory _signature) external returns (bool){
        require( issuers[msg.sender].allwedTypeHash==ACCREDITATION_TYPEHASH, "Only Accreditor can accredit DSOAIssuer");
        require(vc.allwedTypeHash==ACCREDITATION_TYPEHASH);
        issuers[vc.subject]=IssuerMeta( registerCredential(vc, _ipfsHash, _signature),DSOA_TYPEHASH);
        grantRole(ISSUER_ROLE, vc.subject);
        return true;
    }

    function registerDSOACredential(DelegatedVerifiableCredential memory vc, bytes32 _ipfsHash,bytes memory _signature) external returns (bytes32){
        bytes32 digest= registerCredential(vc,_ipfsHash,_signature);
        registerDCCIssuer(digest,vc.subject);
        return digest;
    }

    function registerDCCIssuer(bytes32 digest,address subject) internal returns (bool){
        require((issuers[registry.getIssuer(delegates[msg.sender])].allwedTypeHash==DSOA_TYPEHASH) ||
        issuers[msg.sender].allwedTypeHash==DSOA_TYPEHASH); // Message  sender should be a DSOA Issuer or his delegate 
        issuers[subject]=IssuerMeta( digest,DSOA_TYPEHASH); // Registration has been already done , we just grant role
        grantRole(ISSUER_ROLE, subject);
        return true;
    }

    function registerDCCCredential(DelegatedVerifiableCredential memory vc, bytes32 _ipfsHash,bytes memory _signature) external returns (bytes32) {
        return registerCredential(vc,_ipfsHash,_signature);
    }


    

}

