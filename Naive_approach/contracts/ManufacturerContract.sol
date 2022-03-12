// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./AuthorityContract.sol";
import {Structs} from "./utils/qualityInfrastrucutureLib.sol";

 

/**
    @title ManufacturerContract
    @notice This contract reflects the Manufacturer in the ARD process. Inherits from OpenZeppelin Ownable
 */
contract ManufacturerContract is AccessControl {

    //  Contract state attributes
        // General
            // Roles

                bytes32 public constant AUTHORITY = keccak256("AUTHORITY");
                bytes32 public constant OWNER = keccak256("OWNER");
                bytes32 public constant DELEGATE = keccak256("DELEGATE");

            // Address of the authority contract
                address public authority;

           
        
        // Struct and Map 
            // Device

                mapping (bytes32 => Structs.Device) public devices;  // mapping deviceId => Device data structure 
                bytes32[] public deviceIDs;  // a list of manufacturer's devices by device id
        
            // Delegate

                struct Delegate {
                    address manufacturer;
                    bytes32 name;
                    bytes32 email;
                    bytes32 title;
                }
                mapping(address => Delegate ) delegates; // map delegate address to record
                           
    //  Events

        event DeviceRegistered(bytes32 indexed deviceId,uint64 indexed _validFrom);
        event DeviceUnregistered(bytes32 indexed deviceId,uint64 indexed _validFrom,uint64 indexed _validTo  );
        event DelegateRegistered(address indexed delegate );
        event DelegateUnregistered(address indexed delegate);

    //  Constructor
        /**
            @notice The constructor of the contract expects the EOA manufacturer address to transfer the ownership to, and the address the Authority smart contract
            @param _manufacturer The address of the manufacturer EOA
            @param _authority The address of the AuthorityContract
        */
        constructor (address _manufacturer, address _authority) {
            _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
            authority = _authority;
            grantRole(AUTHORITY, _authority);
            grantRole(OWNER, _manufacturer);
            _setRoleAdmin(DELEGATE,OWNER);
            _setupRole(DEFAULT_ADMIN_ROLE, _authority);
        }

    //  Methods   
        // Manufacturer's related methods
            function registerDevice(bytes32 _deviceName, bytes32 _serial) external {
                    
                    require(hasRole(OWNER,tx.origin)||hasRole(DELEGATE,tx.origin) || hasRole(DEFAULT_ADMIN_ROLE,msg.sender));
                    
                    bytes32 _deviceId = keccak256(abi.encodePacked( address(this),_deviceName,_serial));

                    require(!devices[_deviceId].registered || devices[_deviceId].revoked , "This device is already registered");

                    if(devices[_deviceId].revoked){
                        devices[_deviceId].revoked=false;
                        devices[_deviceId].registered=true;
                    }
                    else{
                        devices[_deviceId].deviceName = _deviceName;
                        devices[_deviceId].serial = _serial;
                        devices[_deviceId].validFrom = uint32(block.timestamp);
                        devices[_deviceId].registered =true ;
                        devices[_deviceId].revoked = false;
                        deviceIDs.push(_deviceId);          // Store manufacturer address in array
                        AuthorityContract a = AuthorityContract(authority);
                        a.addDevice(_deviceId);
                        }  
                    
                    
                    
                    emit DeviceRegistered(_deviceId, uint32(block.timestamp));
            }

            function unregisterDevice(bytes32 _deviceId)  external {

                require(hasRole(OWNER,tx.origin)||hasRole(DELEGATE,tx.origin) || hasRole(DEFAULT_ADMIN_ROLE,msg.sender));
                
                Structs.Device storage d = devices[_deviceId];
                
                require(d.registered && !d.revoked, "A device must be registered to un-register it");

                d.revoked = true;
                d.validTo = uint32(block.timestamp);

                emit DeviceUnregistered(_deviceId,d.validFrom,d.validTo);
            }

            function registerDelegate(address _delegate,bytes32 _name, bytes32 _email , bytes32 _title) external {
                grantRole(DELEGATE,_delegate);
                delegates[_delegate].manufacturer=address(this);
                delegates[_delegate].name=_name;
                delegates[_delegate].email=_email;
                delegates[_delegate].title=_title;
                emit DelegateRegistered( _delegate );
            }

            function unregisterDelegate(address _delegate) external {
                revokeRole(DELEGATE,_delegate);
                emit DelegateUnregistered( _delegate );
            }
        // Authority's related method 
            function addCertificate(bytes32 _devId, bytes32 _certID) external {
                require(hasRole(AUTHORITY,msg.sender));
                devices[_devId].certificates.push(_certID);
            }
        // Getters and utility functions
            function getDeviceById(bytes32 _devId) public view returns(Structs.Device memory) {
                return devices[_devId];
            }

            function getDeviceCount() public view returns (uint) {
                return deviceIDs.length;
            }

            function getDeviceByIndex(uint _index) public view returns (Structs.Device memory) {
                require(_index<deviceIDs.length-1); 
                return devices[deviceIDs[_index]];
            }
        

}