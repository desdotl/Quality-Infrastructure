//SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.0;

import "./lib/ECDSA.sol";
import "../node_modules/@openzeppelin/contracts/access/AccessControlEnumerable.sol";
import "./AbstractClaimsVerifier.sol";
import "./claimTypes/ClaimTypes.sol";
import "./claimTypes/DelegateTypes.sol";

contract ClaimsVerifier is AbstractClaimsVerifier, DelegateTypes, AccessControlEnumerable {

    using ECDSA for bytes32;

    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    struct IssuerMeta {
        bytes32 credentialHash;
        address verifyngContract;
    }

    mapping (address => IssuerMeta) issuers;
    mapping (address => bytes32) delegates;

    event DelegateRegistered(bytes32 indexed delegtaelHash, address issuer, address delegate, uint iat);
    event DelegateRevoked(bytes32 indexed delegtaelHash, address by, uint256 date);

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

        function registerDeleagte (Delegate memory _delegate, bytes32 _ipfsHash, bytes memory _signature)  public onlyIssuer returns(bool) {
            bytes32 _delegateHash = domainHash(_delegate);
            require(!_exist(_delegateHash),"Delegation already registered ");
            require(_validPeriod(_delegate.validFrom, _delegate.validTo),"Invalid period");
            require( DIDregistry.validDelegate(msg.sender, "veriKey",_delegate.subject), "This subject is not an Issuer Delegate");
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := mload(add(_signature, 0x20))
                s := mload(add(_signature, 0x40))
                v := byte(0, mload(add(_signature, 0x60)))
            }
            address signer;
            signer = ecrecover(_delegateHash, v, r, s);
            require(msg.sender==signer,"Signature not corresponding");
            _registerCredential(msg.sender,msg.sender, _delegate.subject, _delegateHash, _delegate.validFrom, _delegate.validTo, _ipfsHash);
            
            delegates[_delegate.subject]= _delegateHash;
            DelegateRegistered( _delegateHash, msg.sender,_delegate.subject, _delegate.validFrom);
            return true;
        }
        function verifyDalegate(VerifiableDelegate memory verified) public view returns (bool){
            Delegate memory _delegate = verified.delegate;
            bytes32 _delegateHash = domainHash(_delegate);
            return _isActiveCredential(_delegateHash) && delegates[_delegate.subject]==_delegateHash;

        }
        function verifyDalegate(address _delegate) public view returns (bool){
            bytes32 _delegateHash = delegates[_delegate];
            return _isActiveCredential(_delegateHash);

        }

        function revokeDelegate(address _delegate) public onlyIssuer returns (bool) {
            require(_isActiveCredential(delegates[_delegate]),"This has delegation been already revoked or expired");
            require(msg.sender==registry.getIssuer(delegates[_delegate]) && msg.sender==registry.getSigner(delegates[_delegate]),"Not authorized to revoke this delegation");
            registry.revokeCredential(delegates[_delegate]);
            return true;
        }

    // Delegated credential

        function registerCredential(DelegatedVerifiableCredential memory vc, bytes32 _ipfsHash,bytes memory _signature) public returns (bool) {
            require(verifyDalegate(vc.issuer) && (msg.sender==vc.issuer.delegate.subject),"Not authorized to register credentials");    
            bytes32 digest = domainHash(vc);
            address signer = digest.recover(_signature);
            require(msg.sender == signer, "Sender hasn't signed the credential");
            _registerCredential(vc.issuer.delegate.issuer,msg.sender, vc.subject, digest, vc.validFrom, vc.validTo, _ipfsHash);
            return true;      
        }
        function verifyCredential(DelegatedVerifiableCredential memory vc, uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
            require(verifyDalegate(vc.issuer),"Error verifiang delegate");
            bytes32 digest = domainHash(vc);
            return (_exist(digest) && !_Revoked(digest) && _verifySigner(digest, vc.issuer.delegate.subject, v, r, s) && _validPeriod(digest));
        }
        function revokeCredential(bytes32 _credentialHash) public returns (bool) {
            require( (hasRole(ISSUER_ROLE,msg.sender)) ||  (verifyDalegate(msg.sender)),"Not authorized to revoke credentials");
            require(_isActiveCredential(_credentialHash),"This has been already revoked or expired");
            address _issuer;
            address _signer;
            _issuer=registry.getIssuer(_credentialHash);
            _signer=registry.getSigner(_credentialHash);
            require(msg.sender==_issuer || msg.sender==_signer,"Not authorized to revoke this credentials");
            registry.revokeCredential(_credentialHash);
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

    // Domain hash

        function domainHash(Delegate memory vd) internal view returns (bytes32){
            return keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    DOMAIN_SEPARATOR,
                    hash(vd)
                )
            ); 
        }

        function domainHash(VerifiableDelegate memory vd) internal view returns (bytes32){
            return keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    DOMAIN_SEPARATOR,
                    hash(vd)
                )
            ); 
        }

        function domainHash(DelegatedVerifiableCredential memory vc) internal view returns (bytes32){
            return keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    DOMAIN_SEPARATOR,
                    hash(vc)
                )
            );
        }

}