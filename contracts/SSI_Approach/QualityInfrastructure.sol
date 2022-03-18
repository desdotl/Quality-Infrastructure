//SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.0;

import "./AbstractClaimsVerifier.sol";

contract QualitiyInfrastructure is AbstractClaimsVerifier {

    // State Variable

        bytes32 constant ID_TYPEHASH=keccak256("ID_TYPEHASH");
        bytes32 constant DSOA_TYPEHASH=keccak256("DSOA_TYPEHASH");
        bytes32 constant DEVID_TYPEHASH=keccak256("DEVID_TYPEHASH");
        bytes32 constant DCC_TYPEHASH=keccak256("DCC_TYPEHASH");
        bytes32 constant ACCREDITATION_TYPEHASH=keccak256("ACCREDITATION_TYPEHASH");
        bool private initialzed=false;

    // Events 

        
        event IssuerRegistered(address indexed issuer, address by);

    // Constructor

        
        constructor (address _registryAddress, address _DIDregistryAddress)
        AbstractClaimsVerifier(
            "EIP712Domain",
            "1",
            648529,
            address(this),
            _registryAddress,
            _DIDregistryAddress
        ) {
            
          
            // register credentialSubject for the relevant credential 

                registry.registerCredentialSubject(ID_TYPEHASH, address(this), ID_TYPEHASH);
                registry.registerCredentialSubject(DSOA_TYPEHASH, address(this),ID_TYPEHASH);
                registry.registerCredentialSubject(DEVID_TYPEHASH, address(this),ID_TYPEHASH);
                registry.registerCredentialSubject(DCC_TYPEHASH, address(this),ID_TYPEHASH);
                registry.registerCredentialSubject(ACCREDITATION_TYPEHASH, address(this),ID_TYPEHASH);
        }

    // Function

        function InitializeAdmin(bytes32 _credentialHash,uint64 _from,uint64 _exp,bytes32 _ipfsHash) external onlyAdmin {
                require(!initialzed,"The contract is already initialized");
                // Register first credential for admin (as an accreditor)
                initialzed=true;
                registry.registerCredential( _credentialHash,uint64(_from), uint64(_exp),_ipfsHash,msg.sender);
                issuers[msg.sender].referenceCredential=_credentialHash;
                issuers[msg.sender].allwedTypeHash=ACCREDITATION_TYPEHASH;
                grantRole(ISSUER_ROLE,msg.sender);
                grantRole(ISSUER_ISSUER_ROLE, msg.sender);
                _setRoleAdmin(ISSUER_ROLE, ISSUER_ISSUER_ROLE);
                IssuerRegistered(msg.sender , msg.sender);

        }

        function registerAccreditorIssuer(VerifiableCredential memory vc, bytes32 _ipfsHash,bytes memory _signature) external onlyAdmin {      
            require(vc.typeHash==ACCREDITATION_TYPEHASH,"wrong typehash");
            bytes32 digest=registerCredential(vc, _ipfsHash, _signature); 
            issuers[vc.subject].referenceCredential=digest;
            issuers[vc.subject].allwedTypeHash=ACCREDITATION_TYPEHASH;
            grantRole(ISSUER_ROLE, vc.subject);
            grantRole(ISSUER_ISSUER_ROLE, vc.subject);
            IssuerRegistered(vc.subject ,msg.sender);        }

        function registerIDIssuer(VerifiableCredential memory vc, bytes32 _ipfsHash,bytes memory _signature) external onlyIssuer {

            require( issuers[msg.sender].allwedTypeHash==ACCREDITATION_TYPEHASH, "Only Accreditor can accredit IDIssuer");
            require(vc.typeHash==ACCREDITATION_TYPEHASH);
            bytes32 digest=registerCredential(vc, _ipfsHash, _signature); 
            issuers[vc.subject].referenceCredential=digest;
            issuers[vc.subject].allwedTypeHash=ID_TYPEHASH;
            grantRole(ISSUER_ROLE, vc.subject);
            IssuerRegistered(vc.subject ,msg.sender);
        }

        function registerDEVIDIssuer(VerifiableCredential memory vc, bytes32 _ipfsHash,bytes memory _signature)  external onlyIssuer {
            require( issuers[msg.sender].allwedTypeHash==ACCREDITATION_TYPEHASH, "Only Accreditor can accredit DEVIDIssuer");
            require(vc.typeHash==ACCREDITATION_TYPEHASH);
            bytes32 digest=registerCredential(vc, _ipfsHash, _signature); 
            issuers[vc.subject].referenceCredential=digest;
            issuers[vc.subject].allwedTypeHash=DEVID_TYPEHASH;
            grantRole(ISSUER_ROLE, vc.subject);
            IssuerRegistered(vc.subject , msg.sender);
        }

        function registerDSOAIssuer(VerifiableCredential memory vc, bytes32 _ipfsHash,bytes memory _signature) external onlyIssuer {
            require( issuers[msg.sender].allwedTypeHash==ACCREDITATION_TYPEHASH, "Only Accreditor can accredit DSOAIssuer");
            require(vc.typeHash==ACCREDITATION_TYPEHASH);
            bytes32 digest=registerCredential(vc, _ipfsHash, _signature); 
            issuers[vc.subject].referenceCredential=digest;
            issuers[vc.subject].allwedTypeHash=DSOA_TYPEHASH;
            grantRole(ISSUER_ROLE, vc.subject);
            grantRole(ISSUER_ISSUER_ROLE, vc.subject);
            IssuerRegistered(vc.subject , msg.sender);
        }

        function registerDSOACredential(VerifiableCredential memory vc, bytes32 _ipfsHash,bytes memory _signature) external returns (bytes32){
            bytes32 digest= registerCredential(vc,_ipfsHash,_signature);
            issuers[vc.subject].referenceCredential=digest;
            issuers[vc.subject].allwedTypeHash=DCC_TYPEHASH;
             // Registration has been already done , we just grant role
            grantRole(ISSUER_ROLE, vc.subject);
            IssuerRegistered(vc.subject , msg.sender);
            return digest;
        }

        

}

