// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;


library Enum{
   
    enum Category{INTERVAL,DISCRETE}
    enum Prefix{Y,Z,E,P,T,G,M,k,h,da,d,c,m,mu,n,p,f,a,z,y}
    enum SIunit{m,sec,kg,K,A,mol,cd}
}

library Structs{


     // Device data structure
    struct Device {

        bytes32 deviceName;
        bytes32 serial;
        bytes32[] certificates;
        uint64 validFrom;
        uint64 validTo;
        bool   revoked;
        bool   registered;
         
    }

    struct Equipment { 
                address propretary;
                bool rented;
                bool active;
                uint64 validFrom;
                uint64 validTo; 
                
            }  

    struct CalibrationCertificate {

        bytes32 devId; // what I am calibrating
        bytes32 certificateLacation; // external URL of Certificate
        bytes32 dcc;
        address responsible; // who is responsible by the calibration
        bool   revoked;
        bool   registered;
        uint64 validFrom;
        uint64 validTo;
       
    }

    struct AccreditationCertificate {

        
        bytes32 certificateLacation; // external URL of Certificate
        bytes32 soa;
        address laboratory; // who is accredited
        uint64 validFrom;
        uint64 validTo;
        address responsible; // who is responsible by the calibration
        bool revoked;
        bool registered;
        
    }

   
}
