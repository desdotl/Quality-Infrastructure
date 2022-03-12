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
                uint64 validFrom;
                uint64 validTo; 
                bool active;
            }  

    struct CalibrationCertificate {

        bytes32 devId; // what I am calibrating
        address responsible; // who is responsible by the calibration
        bytes32[] equipments; // the equipments used for calibration
        //CertificationScope[] scopes;
        bytes32 certificateLacation; // external URL of Certificate
        uint64 validFrom;
        uint64 validTo;
        bool   revoked;
        bool   registered;
    }

    struct AccreditationCertificate {

        address laboratory; // who is accredited
        address responsible; // who is responsible by the calibration
        AccreditationScope[] scopes;
        bytes32 certificateLacation; // external URL of Certificate
        uint64 validFrom;
        uint64 validTo;
        bool revoked;
        bool registered;
    }

    struct AccreditationScope {

        bytes32 AccreditationID;
        Enum.SIunit[] units;
        int32[] exponents;
        Enum.Category category;
        int128 lowerRange; //IEE 754
        int128 upperRange; //IEE 754
        Enum.Prefix prefixMeasure;
        int128 fixedUncertainty;
        int128 measurandCoefficientUncertainty;
        Enum.Prefix prefixUncertainty;
    }

    struct CertificationScope {

        bytes32 CertificationID;
        Enum.SIunit[] units;
        int32[] exponents;
        Enum.Category category;
        int128 lowerRange; //IEE 754
        int128 upperRange; //IEE 754
        Enum.Prefix prefixMeasure;
        int128 fixedUncertainty;
        int128 measurandCoefficientUncertainty;
        Enum.Prefix prefixUncertainty;
    }
}

