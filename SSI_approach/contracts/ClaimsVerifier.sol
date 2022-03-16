//SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.0;

import "../node_modules/@openzeppelin/contracts/access/AccessControlEnumerable.sol";
import "./AbstractClaimsVerifier.sol";
import "./claimTypes/ClaimTypes.sol";
import "./claimTypes/DelegateTypes.sol";

contract ClaimsVerifier is AbstractClaimsVerifier, DelegateTypes, AccessControlEnumerable {


    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    struct IssuerMeta {
       bytes32 CredentialHash;
       bytes32 allwedTypeHash;
    }

    mapping(address=> IssuerMeta) issuers;

    mapping (address => bytes32) delegates;

    event DelegateRegistered(bytes32 indexed delegatedHash, address issuer, address delegate, uint iat);
    event DelegateCredentialRegistered(bytes32 indexed delegatedCredentialHash, address subject, address delegate, uint iat);
    event CredentialRegistered(bytes32 indexed credentialHash, address subject, address issuer, uint iat);
    event CredentialRevoked(bytes32 indexed credentialHash, address by, uint256 date);

    constructor (address _registryAddress, address _DIDregistryAddress)
    AbstractClaimsVerifier(
        "EIP712Domain",
        "1",
        648529,
        address(this),
        _registryAddress,
        _DIDregistryAddress
    ) {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    
    }

    // Delegate 

        function registerDelegate(Delegate memory _delegate, bytes32 _ipfsHash, bytes memory _signature)  external onlyIssuer returns(bool) {

            // Preliminary check 
                require(msg.sender==_delegate.issuer,"The sender is not the issuer");
                require(registry.verifyCredentialSubject(_delegate.allwedTypeHash, address(this), _delegate.version),"CredentialSubject does not exist"); 
                require(_delegate.allwedTypeHash==issuers[_delegate.issuer].allwedTypeHash,"The issuer can not register a delegate for this credentialSubject"); 
                bytes32 _delegateHash = domainHash(_delegate);
                require(!_exist(_delegateHash),"Delegation already registered "); 
                require(_validPeriod(_delegate.validFrom, _delegate.validTo),"Invalid period"); 
                require( DIDregistry.validDelegate(msg.sender, "veriKey",_delegate.subject), "This subject is not an Issuer Delegate");

            //  Registration
                _registerCredential(msg.sender,msg.sender,msg.sender, _delegate.subject, _delegateHash, _delegate.validFrom, _delegate.validTo, _ipfsHash,_signature);
                delegates[_delegate.subject]= _delegateHash;
                DelegateRegistered( _delegateHash, msg.sender,_delegate.subject, _delegate.validFrom);
            return true;
        }

        function _delegationCheck(bytes32 _delegateHash, address subject,bytes32 allwedTypeHash,uint256 version) internal view {
            
            require(_isActiveCredential( _delegateHash),"The delegate credential is inactive (revoked or expired) ");
            require( delegates[subject]==_delegateHash ," The delegate does not exist in the domain"); 
            require(registry.verifyCredentialSubject(allwedTypeHash, address(this), version),"CredentialSubject does not exist"); 
            require( issuers[registry.getIssuer(_delegateHash)].allwedTypeHash==allwedTypeHash, "The credentialSubject isn't correct");
        }

         function verifyDelegate(Delegate memory _delegate, bytes memory _signature) external view returns (bool) {
            
            bytes32 _delegateHash = domainHash(_delegate);
            _delegationCheck(_delegateHash, _delegate.subject,_delegate.allwedTypeHash,_delegate.version);
            require(_verifySigner(_delegateHash, _delegate.issuer,_signature), "Signature isn't correct" );
            return true;
        }

        function  verifyDelegate(VerifiableDelegate memory verified) public view returns (bool){
            
            bytes32 _delegateHash = domainHash(verified.delegate);
            _delegationCheck(_delegateHash, verified.delegate.subject,verified.delegate.allwedTypeHash,verified.delegate.version); 
            require( ecrecover(_delegateHash, verified.v, verified.r, verified.s)==verified.delegate.issuer,"Signature isn't correct ");
            return true;
        }

        function revokeDelegate(address _delegate) external onlyIssuer returns (bool) {
            
            // Preliminary check 
                require(_isActiveCredential(delegates[_delegate]),"This  delegation has been already revoked or expired");
                require(msg.sender==registry.getIssuer(delegates[_delegate]),"The revoker is not the issuer");

            //  Revocation
                registry.revokeCredential(delegates[_delegate]);
            return true;
        }

    // Basic credential

        function registerCredential(VerifiableCredential memory vc, bytes32 _ipfsHash,bytes memory _signature) internal onlyIssuer returns (bytes32)  {
            
            // Preliminary check 
                require(msg.sender==vc.issuer,"Sender is not the issuer");    
                require(registry.verifyCredentialSubject(vc.allwedTypeHash, address(this), vc.version),"CredentialSubject does not exist");
            
            //  Registration
                bytes32 digest = domainHash(vc);
                _registerCredential(msg.sender,msg.sender,msg.sender, vc.subject, digest, vc.validFrom, vc.validTo, _ipfsHash,_signature);
                emit CredentialRegistered(digest, vc.subject, vc.issuer, block.timestamp);
            return digest;      
        }

        function verifyCredential(VerifiableCredential memory vc, bytes memory _signature) internal view returns (bool) {
            
            bytes32 digest = domainHash(vc);
            require(_isActiveCredential( digest),"The credential is inactive (revoked or expired) ");
            require(_verifySigner(digest, vc.issuer,_signature), "Wrong signature" );
            return true;
        }
        

    // Delegated credential

        function registerCredential(DelegatedVerifiableCredential memory vc, bytes32 _ipfsHash,bytes memory _signature) internal returns (bytes32) {

            // Preliminary check 
                require(msg.sender==vc.issuer.delegate.subject,"Sender is not the issuer");    
                require(verifyDelegate(vc.issuer) ,"The delegate for this credential is invalid");
            
            //  Registration

                bytes32 digest = domainHash(vc);
                _registerCredential(msg.sender,vc.issuer.delegate.issuer,msg.sender, vc.subject, digest, vc.validFrom, vc.validTo, _ipfsHash,_signature);
                emit DelegateCredentialRegistered(digest, vc.subject, vc.issuer.delegate.subject, block.timestamp);
                return digest;      
        }

        function verifyCredential(DelegatedVerifiableCredential memory vc, bytes memory _signature) public view returns (bool) {
            require(verifyDelegate(vc.issuer),"The delegate for this credential is invalid");
            bytes32 digest = domainHash(vc);
            require(_isActiveCredential( digest),"The credential is inactive (revoked or expired) ");
            require(_verifySigner(digest, vc.issuer.delegate.subject, _signature), "Wrong signature");
            return true;
        }

    // Credential Revocation ( generic)
        function revokeCredential(bytes32 _credentialHash) public returns (bool) {

        // Preliminary Check
            require( (hasRole(ISSUER_ROLE,msg.sender)) ||  (_isActiveCredential( delegates[msg.sender])),"Not authorized to revoke credentials");
            require(msg.sender==registry.getIssuer(_credentialHash) || msg.sender==registry.getSigner(_credentialHash),"Not authorized to revoke this credentials");
            require(_isActiveCredential(_credentialHash),"This has been already revoked or expired");
        
        // Revocation    
            registry.revokeCredential(_credentialHash);
            CredentialRevoked( _credentialHash,  msg.sender, block.timestamp);
            return true;
        }

    // Utility

        modifier onlyAdmin(){
            require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Caller is not Admin");
            _;
        }

        modifier onlyIssuer() {
            require(hasRole(ISSUER_ROLE, msg.sender), "Caller is not a issuer 1");
            _;
        }

    // Domain hash (solidity does not support generic types)

        function domainHash(Delegate memory vd) internal view returns (bytes32){
            return _domainHash(hash(vd));
        }
         function domainHash(VerifiableDelegate memory vd) internal view returns (bytes32){
            return _domainHash(hash(vd));
        }
         function domainHash(DelegatedVerifiableCredential memory vd) internal view returns (bytes32){
            return _domainHash(hash(vd));
        }
         function domainHash(VerifiableCredential memory vd) internal view returns (bytes32){
            return _domainHash(hash(vd));
        }

         function domainHash1(Delegate memory vd) internal view returns (bytes32){
            return _domainHash(hash(vd));
        }
         function domainHash2(VerifiableDelegate memory vd) internal view returns (bytes32){
            return _domainHash(hash(vd));
        }
         function domainHash3(DelegatedVerifiableCredential memory vd) internal view returns (bytes32){
            return _domainHash(hash(vd));
        }
         function domainHash4(VerifiableCredential memory vd) internal view returns (bytes32){
            return _domainHash(hash(vd));
        }

}