//SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.0;

import "./EIP1812_EIP712/ClaimsVerifier.sol";
import "./DevIDCOntract.sol";
import "./DSOAContract.sol";

contract AuthorityContract is ClaimsVerifier {
   
    constructor(bytes32 _ID_TYPEHASH,
    bytes32 _DSOA_TYPEHASH,
    bytes32 _DEVID_TYPEHASH,
    bytes32 _DCC_TYPEHASH,
    address _registryAddress,
    address firstIssuer, 
    address _DIDregistryAddress, 
    bytes32 _IDcredentialHash, 
    uint256 _from, 
    uint256 _exp, 
    bytes32 _ipfsHash, 
    bytes memory _signature) 
    ClaimsVerifier( _registryAddress,  _DIDregistryAddress){
        
        // set the type hash for ID credential


        // The admin set up the first Issuer

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(_signature, 0x20))
            s := mload(add(_signature, 0x40))
            v := byte(0, mload(add(_signature, 0x60)))
        }

        address signer = ecrecover(_IDcredentialHash, v, r, s);
        require(firstIssuer==signer,"Signature not corresponding");
        
        //registering a selfSigned Credential of Type ID 
        _registerCredential(firstIssuer,firstIssuer, firstIssuer, _IDcredentialHash, _from, _exp, _ipfsHash);

        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        grantRole(ISSUER_ROLE, firstIssuer);
    }

    

}

