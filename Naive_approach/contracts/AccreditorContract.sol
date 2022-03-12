// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./AuthorityContract.sol";
import "./ManufacturerContract.sol";
import {Structs} from "./qualityInfrastrucutureLib.sol";


contract AccreditorContract is AccessControl { 

    //  Contract state attributes
        // General
        // Roles

            bytes32 public constant AUTHORITY = keccak256("AUTHORITY");
            bytes32 public constant OWNER = keccak256("OWNER");
            bytes32 public constant DELEGATE = keccak256("DELEGATE");

        // Address of the authority contract
            address public authority;

    //  Struct and Map 

        // Digital Accreditation Certificate

            mapping (bytes32 => Structs.AccreditationCertificate) certificates;// certificateID to AccreditationCertificate
            bytes32[] certificateIDs; 
    
        // Delegate

            struct Delegate {
                address accreditor;
                bytes32 name;
                bytes32 email;
                bytes32 title;
            }
            mapping(address => Delegate ) delegates; // map delegate address to record

    //  Events 

        event CertificateRegistered(bytes32 indexed _certID,uint64 indexed _validFrom,uint64 indexed _validTo);
        event CertificateRevoked(bytes32 indexed _certID,uint64 indexed _validTo);
        event DelegateRegistered(address indexed delegate );
        event DelegateUnregistered(address indexed delegate);

    //  Constructor
        /**
            @notice The constructor of the contract expects the EOA accreditor address to transfer the ownership to, and the address the Authority smart contract
            @param _accreditor The address of the accreditor EOA
            @param _authority The address of the AuthorityContract
        */
        constructor (address _accreditor, address _authority) {
            _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
            authority = _authority;
            grantRole(AUTHORITY, _authority);
            grantRole(OWNER, _accreditor);
            _setRoleAdmin(DELEGATE,OWNER);
            _setupRole(DEFAULT_ADMIN_ROLE, _authority);
        }
    
    //  Methods   
        // Accreditor's related  Method 
           

            function accredit(address _labID,
                             bytes32 _certificateLacation,
                             uint64 _validTo,
                             Structs.AccreditationScope[] memory _scopes          
                                    ) public {
                require(hasRole(OWNER,tx.origin)||hasRole(DELEGATE,tx.origin) || hasRole(DEFAULT_ADMIN_ROLE,msg.sender));                        
                
                bytes32 _certificateID=keccak256(abi.encodePacked(_labID,address(this),block.timestamp));

                require(!certificates[_certificateID].registered , "This certificate is already registered");
                /*Structs.AccreditationCertificate memory newAcc= Structs.AccreditationCertificate({
                    laboratory:_labID,
                    responsible:tx.origin,
                    scopes:_scopes,
                    validFrom:uint64(block.timestamp),
                    validTo:_validTo,
                    certificateLacation:_certificateLacation,
                    registered:true,
                    revoked:false
                });
                 certificates[_certificateID]=newAcc;*/
                certificates[_certificateID].laboratory=_labID;
                certificates[_certificateID].responsible=tx.origin;
                certificates[_certificateID].validFrom=uint64(block.timestamp);
                certificates[_certificateID].validTo=_validTo;
                certificates[_certificateID].certificateLacation=_certificateLacation;
                certificates[_certificateID].registered=true;
                certificateIDs.push(_certificateID);
                for (uint i=0; i<_scopes.length; i++) {
                    certificates[_certificateID].scopes.push(_scopes[i]);
                }
                AuthorityContract authorityContract = AuthorityContract(authority);
                authorityContract.addAccreditation(_labID,_certificateID);
                emit  CertificateRegistered( _certificateID, uint64(block.timestamp),_validTo);
            }

            function revokeAccreditation(bytes32 _certID) external {

                require(hasRole(OWNER,tx.origin)||hasRole(DELEGATE,tx.origin) || hasRole(DEFAULT_ADMIN_ROLE,msg.sender));

                Structs.AccreditationCertificate storage c = certificates[_certID];
                
                require(c.registered && !c.revoked, "A certificate must be registered tobe revoked");

                c.revoked = true;
                c.validTo = uint32(block.timestamp);
                emit CertificateRevoked(_certID , uint32(block.timestamp));
            }

            function registerDelegate(address _delegate,bytes32 _name, bytes32 _email , bytes32 _title) external {
                grantRole(DELEGATE,_delegate);
                delegates[_delegate].accreditor=address(this);
                delegates[_delegate].name=_name;
                delegates[_delegate].email=_email;
                delegates[_delegate].title=_title;
                emit DelegateRegistered( _delegate );
            }

            function unregisterDelegate(address _delegate) external {
                revokeRole(DELEGATE,_delegate);
                emit DelegateUnregistered( _delegate );
            }

        // Getters and utility functions
            
            function getCertificateById(bytes32 _ID) public view returns (Structs.AccreditationCertificate memory) {
                return certificates[_ID];
            }   

            function getCertificateCount() public view returns (uint) {
                return certificateIDs.length;
            }

            function getCertificateByIndex(uint _index) public view returns (Structs.AccreditationCertificate memory) {
                require(_index<certificateIDs.length-1); 
                return certificates[certificateIDs[_index]];
            }
      
        
}


