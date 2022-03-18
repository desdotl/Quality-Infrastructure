//SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.0;

import "../../node_modules/@openzeppelin/contracts/access/AccessControl.sol";
import "./AbstractClaimsVerifier.sol";
import "./claimTypes/ClaimTypes.sol";
import "./lib/ECDSA.sol";
import "./CredentialRegistry.sol";
import "./EthereumDIDRegistry.sol";



contract AbstractClaimsVerifier  is ClaimTypes, AccessControl {

    using ECDSA for bytes32;
    
    struct EIP712Domain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }

    struct IssuerMeta {
       bytes32 referenceCredential;
       bytes32 allwedTypeHash;
    }

    struct DelegateMeta {
       bytes32 referenceCredential;
       bytes32 allwedTypeHash;
    }
    
    mapping(address=> IssuerMeta) issuers;

    mapping (address => DelegateMeta) delegates;

    CredentialRegistry registry;
    EthereumDIDRegistry DIDregistry;

    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");
    bytes32 public constant ISSUER_ISSUER_ROLE = keccak256("ISSUER_ROLE");

    bytes32 constant EIP712DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 DOMAIN_SEPARATOR;


    event DelegateRegistered(address indexed delegate, address by);
    event DelegateRevoked(address indexed delegate,address by, uint256 date);   

   
     constructor (
        string memory name,
        string memory version,
        uint256 chainId,
        address verifyingContract,
        address _registryAddress,
        address _DIDregistryAddress) {
        DOMAIN_SEPARATOR = hashEIP712Domain(
            EIP712Domain({
        name : name,
        version : version,
        chainId : chainId,
        verifyingContract : verifyingContract
        }));
        registry = CredentialRegistry(_registryAddress);
        DIDregistry = EthereumDIDRegistry(_DIDregistryAddress);
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }
    
    

    // Delegate 

        function registerDelegate(Delegate memory _delegate, bytes32 _ipfsHash, bytes memory _signature) external onlyIssuer {

            // Preliminary check 
                require(msg.sender==_delegate.issuer,"Wrong Sender");
                require(_validPeriod(_delegate.validFrom, _delegate.validTo),"Invalid period");
                require( DIDregistry.validDelegate(msg.sender, "veriKey",_delegate.subject), "Wrong Subject");

            //  Registration
                bytes32 _delegateHash = domainHash(_delegate);
                require(msg.sender== _delegateHash.recover(_signature),"Wrong Signer");
                registry.registerCredential(_delegateHash,uint64( _delegate.validFrom),uint64(_delegate.validTo),_ipfsHash,msg.sender);
                delegates[_delegate.subject]= DelegateMeta(_delegateHash,_delegate.allwedTypeHash);

            //  Registration event
                DelegateRegistered(_delegate.subject,msg.sender);
        }

        function revokeDelegate(address _delegate) external onlyIssuer {

            require(registry.isActiveCredential(delegates[_delegate].referenceCredential,msg.sender));
            registry.revokeCredential(delegates[_delegate].referenceCredential,msg.sender);
            DelegateRevoked( _delegate,msg.sender, block.timestamp);
        }

    // Basic credential

        function registerCredential(VerifiableCredential memory vc, bytes32 _ipfsHash,bytes memory _signature) public  returns (bytes32)  {
            
            // Preliminary check 
                
                bytes32  digest = domainHash(vc);
                address  signer =  digest.recover(_signature);
                require(msg.sender == signer,"Wrong Signer");
                require(_validPeriod(vc.validFrom, vc.validTo),"Invalid period");
                require(registry.verifyCredentialSubject(vc.typeHash, address(this), vc.version),"CredentialSubject does not exist");
                if (vc.issuer != signer)
                    require (registry.isActiveCredential(delegates[msg.sender].referenceCredential,vc.issuer) && 
                            delegates[msg.sender].allwedTypeHash==vc.typeHash,"Wrong Delegate" );
                else 
                    require( (hasRole(ISSUER_ROLE, msg.sender) && issuers[msg.sender].allwedTypeHash==vc.typeHash),"Wrong issuer");
                registry.registerCredential(digest, uint64(vc.validFrom),uint64(vc.validTo), _ipfsHash,vc.issuer);
                return digest;      
        }

        
        function revokeCredential(bytes32 _credentialHash,address issuer) external {

                    require (registry.isActiveCredential(_credentialHash,issuer) && 
                    (msg.sender == issuer || registry.isActiveCredential(delegates[msg.sender].referenceCredential,issuer)),
                    "Not Authorized");
            registry.revokeCredential(_credentialHash,issuer);
        }

    //  Verify Credential

        function verifyCredential(VerifiableCredential memory vc, bytes memory _signature) external view returns (bool) {
            
            bytes32 digest = domainHash(vc);
            address _signer = digest.recover(_signature);
            require(_signer==vc.issuer, "Wrong signature" );
            require( registry.isActiveCredential( digest,_signer),"The credential is inactive (revoked or expired) ");
            return true;
        }

        function  verifyCredential(Delegate memory vc, bytes memory _signature) public view returns (bool){
            bytes32 digest = domainHash(vc);
            address _signer = digest.recover(_signature);
            require(_signer==vc.issuer, "Wrong signature" );
            require( registry.isActiveCredential( digest,_signer),"The credential is inactive (revoked or expired) ");
            return true;
        }

        function verifyCredential(bytes32 digest, bytes memory _signature) external view returns (bool) {
            
            address _signer = digest.recover(_signature);
            require( registry.isActiveCredential( digest,_signer),"The credential is inactive (revoked or expired) ");
            return true;
        }

    // Getter 
        function getIssuerType(address _issuer) external view returns(bytes32){
            return issuers[_issuer].allwedTypeHash;
        }
        

        function getDelegateType(address _delegate) external view returns(bytes32){
            return delegates[_delegate].allwedTypeHash;
        }

        function isActiveDelegate(address issuer) external view  returns (bool) {
            return registry.isActiveCredential(delegates[msg.sender].referenceCredential,issuer);
        }

        function getDelegate(address _delegate) external view returns(DelegateMeta memory){
            return delegates[_delegate];
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

        function _validPeriod(uint256 _validFrom, uint256 _validTo) internal view returns (bool) {
        return (_validFrom <= block.timestamp) && (block.timestamp < _validTo);
    }

        function _domainHash(bytes32 _hash) internal view returns (bytes32){
            return keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    DOMAIN_SEPARATOR,
                    _hash
                )
            ); 
        }

        function hashEIP712Domain(EIP712Domain memory eip712Domain) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712DOMAIN_TYPEHASH,
                keccak256(bytes(eip712Domain.name)),
                keccak256(bytes(eip712Domain.version)),
                eip712Domain.chainId,
                eip712Domain.verifyingContract
            )
        );
    }  

    // Domain hash (solidity does not support generic types)

        function domainHash(Delegate memory vd) internal view returns (bytes32){
            return _domainHash(hash(vd));
        }
       
        function domainHash(VerifiableCredential memory vd) internal view returns (bytes32){
            return _domainHash(hash(vd));
        }

        function domainHash1(Delegate memory vd) public view returns (bytes32){
            return _domainHash(hash(vd));
        }
        function domainHash4(VerifiableCredential memory vd) public view returns (bytes32){
            return _domainHash(hash(vd));
        }

       


}