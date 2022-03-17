// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "../../node_modules/@openzeppelin/contracts/access/AccessControl.sol";
import "./AuthorityContract.sol";
import "./ManufacturerContract.sol";
import {Structs} from "./utils/qualityInfrastrucutureLib.sol";


contract LaboratoryContract is AccessControl { 

    //  Contract state attributes
        // General
        // Roles

            bytes32 public constant AUTHORITY = keccak256("AUTHORITY");
            bytes32 public constant OWNER = keccak256("OWNER");
            bytes32 public constant DELEGATE = keccak256("DELEGATE");

        
        // authority contract
            
            AuthorityContract authorityContract;

    //  Struct and Map 
        // Equipment

           
            mapping (bytes32 => Structs.Equipment) equipments; // deviceID to Equimpent;
            bytes32[] equipmentIDs;

        // Digital Calibration Certificate

            mapping (bytes32 => Structs.CalibrationCertificate) certificates;// certificateID to CalibrationCertificate
            bytes32[] certificateIDs; // The actual certificates 
    
        // Delegate

            struct Delegate {
                address laboratory;
                bytes32 name;
                bytes32 email;
                bytes32 title;
            }
            mapping(address => Delegate ) delegates; // map delegate address to record

    //  Events 

        event EquipmentRegistered(bytes32 indexed _devID,uint64 indexed _validFrom,uint64 indexed _validTo);
        event EquipmentUnregistered(bytes32 indexed _devID,uint64 indexed _validFrom,uint64 indexed _validTo);
        event CertificateRegistered(bytes32 indexed _certID,uint64 indexed _validFrom,uint64 indexed _validTo);
        event CertificateRevoked(bytes32 indexed _certID,uint64 indexed _validTo);
        event DelegateRegistered(address indexed delegate );
        event DelegateUnregistered(address indexed delegate);

    //  Constructor
        /**
            @notice The constructor of the contract expects the EOA laboratory address to transfer the ownership to, and the address the Authority smart contract
            @param _laboratory The address of the laboratory EOA
            @param _authority The address of the AuthorityContract
        */
        constructor (address _laboratory, address _authority) {
            _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
            grantRole(AUTHORITY, _authority);
            grantRole(OWNER, _laboratory);
            _setRoleAdmin(DELEGATE,OWNER);
            _setupRole(DEFAULT_ADMIN_ROLE, _authority);
            authorityContract = AuthorityContract(_authority);
        }
    
    //  Methods   
        // Laboratory's related  Method 
            function registerEquipment(bytes32 _devID,
                                    address _propretary,
                                    bool _rented,
                                    uint64 _validTo) external {
                        
                require(hasRole(OWNER,tx.origin)||hasRole(DELEGATE,tx.origin) || hasRole(DEFAULT_ADMIN_ROLE,msg.sender));
                // we only go through if equipment is not already initialized
                Structs.Equipment memory _equipment = equipments[_devID];
                require( _equipment.active==false || _equipment.validTo<block.timestamp, "This equipment is already registered."); 
                    equipments[_devID].active=true;
                    equipments[_devID].propretary=_propretary;
                    equipments[_devID].rented=_rented;   
                    equipments[_devID].validFrom=uint64(block.timestamp);
                    equipments[_devID].validTo=_validTo;
                    equipmentIDs.push(_devID);
                    emit EquipmentRegistered( _devID, uint64(block.timestamp), _validTo);   
            } 

            function unregisterEquipment(bytes32 _devID) external{
                require(hasRole(OWNER,tx.origin)||hasRole(DELEGATE,tx.origin) || hasRole(DEFAULT_ADMIN_ROLE,msg.sender));
                Structs.Equipment memory _equipment = equipments[_devID];
                require( _equipment.active==true && _equipment.validTo>block.timestamp, "This equipment is already registered.");
                equipments[_devID].active=false;
            }  

            function certify(bytes32 _devID,
                            bytes32   _certificateLacation,
                            uint64 _validTo,
                            bytes32 dcc            
                                    ) external {
                require(hasRole(OWNER,tx.origin)||hasRole(DELEGATE,tx.origin) || hasRole(DEFAULT_ADMIN_ROLE,msg.sender),"Wrong Sender");                        
                
                bytes32 _certificateID=keccak256(abi.encodePacked(_devID,address(this),block.timestamp));

                require(!certificates[_certificateID].registered , "This device is already registered");
                certificates[_certificateID].devId=_devID;
                certificates[_certificateID].responsible=tx.origin;
                certificates[_certificateID].validFrom=uint64(block.timestamp);
                certificates[_certificateID].validTo=_validTo;
                certificates[_certificateID].certificateLacation=_certificateLacation;
                certificates[_certificateID].registered=true;
                certificates[_certificateID].dcc=dcc;
                certificateIDs.push(_certificateID);
                authorityContract.addCertificate(_devID,_certificateID);
                
                emit  CertificateRegistered(_certificateID, uint64(block.timestamp), _validTo);
            }

            function revokeCertificate(bytes32 _certID) external {

                require(hasRole(OWNER,tx.origin)||hasRole(DELEGATE,tx.origin) || hasRole(DEFAULT_ADMIN_ROLE,msg.sender));

                Structs.CalibrationCertificate storage c = certificates[_certID];
                
                require(c.registered && !c.revoked, "A certificate must be registered tobe revoked");

                c.revoked = true;
                c.validTo = uint32(block.timestamp);
                emit CertificateRevoked(_certID , uint32(block.timestamp));
            }

            function registerDelegate(address _delegate,bytes32 _name, bytes32 _email , bytes32 _title) external {
                grantRole(DELEGATE,_delegate);
                delegates[_delegate].laboratory=address(this);
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

            function getEquipmentById(bytes32 _ID) public view returns (Structs.Equipment memory) {
                return equipments[_ID] ;
            } 

            function getEquipmentCount() external view returns (uint) {
                return equipmentIDs.length;
            }
            
            function getEquipmentbyIndex(uint _index) public view returns (Structs.Equipment memory) {
                require(_index<equipmentIDs.length-1); 
                return equipments[equipmentIDs[_index]];
            }
            
            
            function getCertificateById(bytes32 _ID) public view returns (Structs.CalibrationCertificate memory) {
                return certificates[_ID];
            }   

            function getCertificateCount() public view returns (uint) {
                return certificateIDs.length;
            }

            function getCertificateByIndex(uint _index) public view returns (Structs.CalibrationCertificate memory) {
                require(_index<certificateIDs.length-1); 
                return certificates[certificateIDs[_index]];
            }

            function getCertificateIDByIndex(uint _index) public view returns (bytes32) {
                require(_index<certificateIDs.length-1); 
                return certificateIDs[_index];
            }
      
        
}


