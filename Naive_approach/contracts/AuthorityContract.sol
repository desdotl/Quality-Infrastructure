// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./ManufacturerContract.sol";
import "./ManufacturerFactory.sol";
import "./LaboratoryContract.sol";
import "./LaboratoryFactory.sol";
import "./AccreditorContract.sol";
import "./AccreditorFactory.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
    @title AuthorityContract
    @notice This contract reflects the Authority in the ARD process. Inherits from OpenZeppelin Ownable, SOFIE InterledgerSenderInterface and InterledgerReceiverInterface
 */
contract AuthorityContract is AccessControl{

        bytes32 public constant AUTHORITY = keccak256("AUTHORITY");
        bytes32 public constant ACCREDITOR = keccak256("ACCREDITOR");
        bytes32 public constant LABORATORY = keccak256("LABORATORY");
        bytes32 public constant MANUFACTURER = keccak256("MANUFACTURER");


    //   Contract state attributes   
        // Factory contracts
                ManufacturerFactory public manufacturerFactory;
                LaboratoryFactory public laboratoryFactory;
                AccreditorFactory public accreditorFactory;
            
        // Structs and mapping
            // Manufacturer
                struct ManufacturerRecord {
                    bytes32 name;
                    bytes32 _address;
                    bytes32 phonenumber;
                    bytes32 email;
                    uint32 registeredSince;   // registration timestamp
                    uint32 unregisteredSince;   // unregistration timestamp
                }

                // Data structures to map the address of a ManufacturerContract to a Manufacturer data structure
                mapping(address => ManufacturerRecord) public manufacturerRecords;
                // Data structures to map the address of a EOA Manufacturer to a ManufacturerContract
                mapping(address => address ) private manufacturerMap;

                address[] ManufacturerContractIDs;

                mapping ( bytes32 => address) devID2Manufaturer; //Tracking devive to manufacturer

            // Laboratory
                struct LaboratoryRecord {
                    bytes32 name;
                    bytes32 _address;
                    bytes32 phonenumber;
                    bytes32 email;
                    uint32 registeredSince;   // registration timestamp
                    uint32 unregisteredSince;   // unregistration timestamp
                    bool accreditated;
                    bytes32[] accreditationIDs;
                }

                // Data structures to map the address of a LaboratoryContract to a Laboratory data structure
                mapping(address => LaboratoryRecord) public laboratoryRecords;
                // Data structures to map the address of a EOA Laboratory to a LaboratoryContract
                mapping(address => address ) private laboratoryMap;

                address[] laboratoryContractIDs;

                mapping ( bytes32 => address) certID2Laboratory; //Tracking certificate to laboratory
                
            // Accreditor
                struct AccreditorRecord {
                    bytes32 name;
                    bytes32 _address;
                    bytes32 phonenumber;
                    bytes32 email;
                    uint32 registeredSince;   // registration timestamp
                    uint32 unregisteredSince;   // unregistration timestamp
                }

                // Data structures to map the address of a AccreditorContract to a Accreditor data structure
                mapping(address => AccreditorRecord) public accreditorRecords;
                // Data structures to map the address of a EOA Accreditor to a AccreditorContract
                mapping(address => address ) private accreditorMap;

                address[] accreditorContractIDs;

                mapping ( bytes32 => address) certID2Accreditor; //Tracking certificate to accreditor


    // Events 

        event ManufacturerRegistered(address indexed manufacturer, address indexed manufacturerContract);
        event ManufacturerUnregistered(address indexed manufacturer, address indexed manufacturerContract);
        event LaboratoryRegistered(address indexed laboratory, address indexed laboratoryContract);
        event LaboratoryUnregistered(address indexed laboratory, address indexed laboratoryContract);
        event AccreditorRegistered(address indexed accreditor, address indexed accreditorContract);
        event AccreditorUnregistered(address indexed accreditor, address indexed accreditorContract);

    // Constructor 
            
        constructor () {
            manufacturerFactory = new ManufacturerFactory();
            laboratoryFactory = new LaboratoryFactory();
            accreditorFactory = new AccreditorFactory();
            
            _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
            grantRole(AUTHORITY, msg.sender);
        }

    
    //  Methods 
        //  Manufacturer's related methods
            // Registration
                function registerManufacturer(address _manufacturer, bytes32 _name, bytes32 __address,bytes32 _phonenumber,bytes32 _email)  external {
                    require(hasRole(AUTHORITY, msg.sender));
                    require(!hasRole(MANUFACTURER,manufacturerMap[_manufacturer]), "This manufacturer is already registered");

                    ManufacturerContract contractManufacturerAddress = manufacturerFactory.createManufacturerContract(_manufacturer);
                    manufacturerRecords[address(contractManufacturerAddress)].name=_name;
                    manufacturerRecords[address(contractManufacturerAddress)]._address=__address;
                    manufacturerRecords[address(contractManufacturerAddress)].phonenumber=_phonenumber;
                    manufacturerRecords[address(contractManufacturerAddress)].email=_email;
                    manufacturerRecords[address(contractManufacturerAddress)].registeredSince=uint32(block.timestamp);
                    manufacturerMap[_manufacturer]= address(contractManufacturerAddress);                                    
                    ManufacturerContractIDs.push(address(contractManufacturerAddress)); 
                    grantRole(MANUFACTURER, address(contractManufacturerAddress));
                    emit ManufacturerRegistered(_manufacturer, address(contractManufacturerAddress));
                }  
                function unregisterManufacturer(address _manufacturer)  external {
                    require(hasRole(AUTHORITY, msg.sender));
                    require(hasRole(MANUFACTURER,manufacturerMap[_manufacturer]),"This manufacturer is already unregistered");

                    // Deactivate the Manufacturer contract
                    address _manufacturerContract= manufacturerMap[_manufacturer];
                    ManufacturerRecord storage record = manufacturerRecords[_manufacturerContract];
                    record.unregisteredSince = uint32(block.timestamp);
                    revokeRole(MANUFACTURER, manufacturerMap[_manufacturer]);
                    emit ManufacturerUnregistered(_manufacturer,_manufacturerContract);
                }
            // Getter 
                function getManufacturerFactoryContractAddress() external view returns (address){
                    return address(manufacturerFactory);
                }
                function getManufacturerContractbyEOAAddress(address _manufacturer) external view returns (address _manufacturerContract){
                    return manufacturerMap[_manufacturer];
                }
                function getManufacturerCount() external view returns (uint){
                    return ManufacturerContractIDs.length;
                }
                function getManufacturerContractbyIndex(uint indx) external view returns (address){
                    require(( indx<ManufacturerContractIDs.length-1), "not valid index");
                    return ManufacturerContractIDs[indx];
                }
                function getManufacturerRecord(address _address) external view returns ( ManufacturerRecord memory) {

                        if (manufacturerMap[_address]!=address(0))
                            return  manufacturerRecords[manufacturerMap[_address]];
                        else
                            return  manufacturerRecords[_address];

                }  
                function getDeviceManufacturer(bytes32 _devID) external view returns (address) {
                    return devID2Manufaturer[_devID];
                }

        //  Laboratory's related methods
            // Registration 
                function registerLaboratory(address _laboratory, bytes32 _name, bytes32 __address,bytes32 _phonenumber,bytes32 _email)  external {
                    require(hasRole(AUTHORITY, msg.sender));
                    require(!hasRole(LABORATORY,laboratoryMap[_laboratory]), "This laboratory is already registered");

                    LaboratoryContract contractLaboratoryAddress = laboratoryFactory.createLaboratoryContract(_laboratory);
                    laboratoryMap[_laboratory]= address(contractLaboratoryAddress); 
                    laboratoryRecords[address(contractLaboratoryAddress)].name = _name;
                    laboratoryRecords[address(contractLaboratoryAddress)]._address =__address;
                    laboratoryRecords[address(contractLaboratoryAddress)].phonenumber =_phonenumber;
                    laboratoryRecords[address(contractLaboratoryAddress)].email =_email;
                    laboratoryRecords[address(contractLaboratoryAddress)].registeredSince =uint32(block.timestamp); 
                    laboratoryContractIDs.push(address(contractLaboratoryAddress)); 
                    grantRole(LABORATORY,address(contractLaboratoryAddress));
                    emit LaboratoryRegistered(_laboratory, address(contractLaboratoryAddress));
                }
                function unregisterLaboratory(address _laboratory)  external {
                    require(hasRole(AUTHORITY, msg.sender));
                    require(hasRole(LABORATORY,laboratoryMap[_laboratory]),"This laboratory is already unregistered");

                    // Deactivate the Laboratory contract
                    address _laboratoryContract= laboratoryMap[_laboratory];
                    LaboratoryRecord storage record = laboratoryRecords[_laboratoryContract];
                    record.unregisteredSince = uint32(block.timestamp);
                    revokeRole(LABORATORY,laboratoryMap[_laboratory]);
                    emit LaboratoryUnregistered(_laboratory,_laboratoryContract);
                }
            // Getter 
                function getLaboratoryFactoryContractAddress() external view returns (address){
                    return address(laboratoryFactory);
                }
                function getLaboratoryContractbyEOAAddress(address _laboratory) external view returns (address _laboratoryContract){
                    return laboratoryMap[_laboratory];
                } 
                function getLaboratoryCount() external view returns (uint){
                        return laboratoryContractIDs.length;
                }
                function getLaboratoryContractbyIndex(uint indx) external view returns (address){
                        require(( indx<laboratoryContractIDs.length-1), "not valid index");
                        return laboratoryContractIDs[indx];
                }    
                function getLaboratoryRecord(address _address) external view returns ( LaboratoryRecord memory) {

                            if (laboratoryMap[_address]!=address(0))
                                return  laboratoryRecords[laboratoryMap[_address]];
                            else
                                return  laboratoryRecords[_address];

                }  
                function getCertificateLaboratory(bytes32 _certID) external view returns (address) {
                        return certID2Laboratory[_certID];
                }
        //  Accreditor's related methods
            // Registration 
                function registerAccreditor(address _accreditor, bytes32 _name, bytes32 __address,bytes32 _phonenumber,bytes32 _email)  external {
                    require(hasRole(AUTHORITY, msg.sender));
                    require(!hasRole(ACCREDITOR,accreditorMap[_accreditor]), "This accreditor is already registered");

                    AccreditorContract contractAccreditorAddress = accreditorFactory.createAccreditorContract(_accreditor);
                    accreditorRecords[address(contractAccreditorAddress)].name = _name;
                    accreditorRecords[address(contractAccreditorAddress)]._address =__address;
                    accreditorRecords[address(contractAccreditorAddress)].email =_email;
                    accreditorRecords[address(contractAccreditorAddress)].registeredSince=uint32(block.timestamp);
                    accreditorRecords[address(contractAccreditorAddress)]. phonenumber=_phonenumber;
                    accreditorMap[_accreditor]= address(contractAccreditorAddress);
                    accreditorContractIDs.push(address(contractAccreditorAddress)); 
                    grantRole(ACCREDITOR,address(contractAccreditorAddress));
                    emit AccreditorRegistered(_accreditor, address(contractAccreditorAddress));
                }
                function unregisterAccreditor(address _accreditor)  external {
                    require(hasRole(AUTHORITY, msg.sender));
                    require(hasRole(ACCREDITOR,accreditorMap[_accreditor]),"This accreditor is already unregistered");

                    // Deactivate the Accreditor contract
                    address _accreditorContract= accreditorMap[_accreditor];
                    AccreditorRecord storage record = accreditorRecords[_accreditorContract];
                    record.unregisteredSince = uint32(block.timestamp);
                    revokeRole(ACCREDITOR,accreditorMap[_accreditor]);
                    emit AccreditorUnregistered(_accreditor,_accreditorContract);
                }
            // Getter 
                function getAccreditorFactoryContractAddress() external view returns (address){
                    return address(accreditorFactory);
                }
                function getAccreditorContractbyEOAAddress(address _accreditor) external view returns (address _accreditorContract){
                    return accreditorMap[_accreditor];
                } 
                function getAccreditorCount() external view returns (uint){
                        return accreditorContractIDs.length;
                }
                function getAccreditorContractbyIndex(uint indx) external view returns (address){
                        require(( indx<accreditorContractIDs.length-1 ), "not valid index");
                        return accreditorContractIDs[indx];
                }    
                function getAccreditorRecord(address _address) external view returns ( AccreditorRecord memory) {

                            if (accreditorMap[_address]!=address(0))
                                return  accreditorRecords[accreditorMap[_address]];
                            else
                                return  accreditorRecords[_address];

                }  
                function getCertificateAccreditor(bytes32  _certID) external view returns (address) {
                        return certID2Accreditor[_certID];
                }

        // IntraContract Related Method
            function addAccreditation(address _labId, bytes32  _certID) external {
                require(hasRole(ACCREDITOR, msg.sender),"Not an Accreditor");
                certID2Accreditor[_certID]=msg.sender;
                laboratoryRecords[_labId].accreditationIDs.push(_certID);
            }
            function addCertificate(bytes32  _devId, bytes32  _certID) external {
                require(hasRole(LABORATORY, msg.sender),"Not a Laboratory");
                ManufacturerContract _manufacturer=  ManufacturerContract(devID2Manufaturer[_devId]);
                _manufacturer.addCertificate( _devId, _certID);
                certID2Laboratory[_certID]=msg.sender;
            }
            function addDevice(bytes32 _devID) external {
                require(hasRole(MANUFACTURER, msg.sender),"Not a Manufacturer");
                devID2Manufaturer[_devID]=msg.sender;
            }

  
}