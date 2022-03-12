//SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.0;

import "./lib/ECDSA.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "./AbstractClaimsVerifier.sol";
import "./claimTypes/ClaimTypes.sol";
import "./claimTypes/DelegateTypes.sol";

contract ClaimsVerifier is AbstractClaimsVerifier, ClaimTypes, EnumerableAccessControl {

    using ECDSA for bytes32;

    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    struct IssuerMeta {
        bytes32 credentialHash;
        address verifyngContract;
    }
    struct DelegateMeta {
        bytes32 credentialHash;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    mapping (address => IssuerMeta) issuers;
    mapping (address => DelegateMeta) delegates;

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

    function registerCredential(address _issuer, address _subject, bytes32 _credentialHash, uint256 _from, uint256 _exp, bytes32 _ipfsHash,bytes _signature) public onlyIssuer returns (bool) {
            address signer = _credentialHash.recover(_signature);
            require(msg.sender == signer, "Sender hasn't signed the credential");
            return _registerCredential(_issuer,msg.sender, _subject, _credentialHash, _from, _exp, _ipfsHash);
    }

    function verifyCredential(VerifiableCredential memory vc, uint8 v, bytes32 r, bytes32 s) public view returns (bool, bool, bool, bool) {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                hash(vc)
            )
        );
        return (_exist(digest), _verifyRevoked(digest), _verifySigner(digest, vc.issuer, v, r, s), _validPeriod(vc.validFrom, vc.validTo));
    }

    function revokeCredential(bytes32 _credentialHash) external returns (bool) {
        require(hasRole(ISSUER,msg.sender) || verifyDalegate(msg.sender),"Not authorized to revoke this credential");
        registry.revokeCredential(_credentialHash);
        return true;
    }

    function registerDeleagte (address _subject,bytes32 _delegateHash,uint256 _from,uint256 _exp, bytes32 _ipfsHash, bytes memory _signature)  public onlyIssuer returns(bool) {
            
        require(!_exist(_delegateHash) && !_validPeriod(_from, _exp),"Delegate already registered and active ");
        require( DIDregistry.validDelegate(msg.sender, "veriKey",_subject), "This subject is not an Issuer Delegate");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(_signature, 0x20))
            s := mload(add(_signature, 0x40))
            v := byte(0, mload(add(_signature, 0x60)))
        }
        signer = ecrecover(_digest, _v, _r, _s);
        require(msg.sender==signer,"Signature not corresponding");
        _registerCredential(msg.sender,msg.sender, _subject, _delegateHash, _from, _exp, _ipfsHash);
        
        delegates[_subject].credentialHash= _delegateHash;
        delegates[_subject].r=r;
        delegates[_subject].s=s;
        delegates[_subject].v=v;
        DelegateRegistered( _delegtaelHash, msg.sender,_subject, _from);
        return true;
    }


     function verifyDalegate(address _delegate )returns (bool){
          delegates[_delegate].credential

    }

    
    
    function verifyCredential(DelegatedVerifiableCredential memory vc, uint8 v, bytes32 r, bytes32 s) public view returns (bool, bool, bool, bool) {
        if (!verify(vc.issuer))
            return (false,false,false,false);
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                hash(vc)
            )
        );
        // verifica la registrazione 
        return (_exist(digest),_verifyRevoked(digest),_verifySigner(digest, vc.issuer.delegate.subject, v, r, s),_validPeriod(vc.validFrom, vc.validTo));
    }

   

  

    

    function validDalegate(address _delegate )returns (bool){


    }

    function revokeDelegate(address _delegate) public onlyIssuer returns (bool) {
        require(condition);
        require(!delegationExpired(_delegate), "Delegate is already revoked");
    }

    modifier onlyAdmin(){
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Caller is not Admin");
        _;
    }

    modifier onlyIssuer() {
        require(hasRole(ISSUER_ROLE, msg.sender), "Caller is not a issuer 1");
        _;
    }

    function verify(VerifiableDelegate memory verified) public view returns (bool) {
        Delegate memory claim = verified.delegate;
        bytes32 digest = keccak256(
        abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            hash(claim)
        )
        );
        return _verifyIssuer(digest, claim.issuer, verified.v, verified.r, verified.s) 
        && _verifyDelegation(digest, claim.issuer, verified.v, verified.r, verified.s)
        &&  hasRole(ISSUER_ROLE,  claim.issuer) 
        && _validPeriod(claim.validFrom, claim.validTo);
    }




}