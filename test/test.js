const web3Utils = require("web3-utils");
const ethUtil = require("ethereumjs-util");
const console = require('console');
const assert = require('assert');

/**
 * NAIVE APPROACH
 */

// Artifacts

const Authority = artifacts.require("AuthorityContract");
const LaboratoryContract = artifacts.require("LaboratoryContract");
const ManufacturerContract = artifacts.require("ManufacturerContract");
const AccreditorContract = artifacts.require("AccreditorContract");

// utility function

const bytes32= "0x766572694b657900000000000000000000000000000000000000000000000000";

contract("Naive Quality Infrastructure", accounts => {


	const authority = {
		address: '0x47adc0faa4f6eb42b499187317949ed99e77ee85',
		privateKey: 'effa7c6816819ee330bc91f1623f3c66a9fed268ecd5b805a002452075b26c0b'
	};
	const manufacturer = {
		address: '0x4a5a6460d00c4d8c2835a3067f53fb42021d5bb9',
		privateKey: '09288ce70513941f8a859361aeb243c56d5b7a653c1c68374a70385612fe0c2a'
	};
	const accreditor = {
		address: '0x4222ec932c5a68b80e71f4ddebb069fa02518b8a',
		privateKey: '6ccfcaa51011057276ef4f574a3186c1411d256e4d7731bdf8743f34e608d1d1'
	};
	const laboratory = {
		address: '0x4ef9e4721bbf02b84d0e73822ee4e26e95076b9d',
		privateKey: '258b7f85027d7b20f74ecfbfca556aad8eff933365fe5b7473355040c09db418'
	};
	const dccIssuer = {
		address: '0x2da061c6cfa5c23828e9d8dfbe295a22e8779712',
		privateKey: '60090a13d72f682c03db585bf6c3a296600b5d50598a9ceef3291534dede6bea'
	}
	const dccDelegate = {
		address: '0xc1f061d629bbba139dbd07f2eb6a9252a45514c7',
		privateKey: 'e25f43772b0d8f19b0a768dfa779ec2f1422241dfe75293de879dc76607b0405'
	};
	const device = {
		address: '0xf8e160be646d2429c64d46fba8e8588b8483dbaf',
		privateKey: '5644e113a0db2e89243741a31dfae322a20c09cc0025826288bf37725464ce34'
	};

	const delegate = {
		address: '0xae1708b0af10bf1fbee6b4b4220d9453f6007eeb',
		privateKey: '7381f9ee53c41bde0d83e2e69a39f9ddfab74da872d653271a2a9ba050670583'
	}

	const vf =1647417846;
	const vt = vf + 31536000;
	
	it("should register a Manufacturer", async () => {
		const instance = await Authority.deployed();
		let result = await instance.registerManufacturer(manufacturer.address, bytes32, bytes32,bytes32 ,bytes32 )
		let gas=result.receipt["cumulativeGasUsed"];
		console.log("\n\n\ MANUFACTURER REGISTRATION \n The gas used is: "+ gas); 
	});

	it("should register an Accreditor", async () => {
		const instance = await Authority.deployed();
		let result = await instance.registerAccreditor(accreditor.address, bytes32, bytes32,bytes32 ,bytes32 )
		let gas=result.receipt["cumulativeGasUsed"];
		console.log("\n\n\ ACCREDITATION BODY REGISTRATION \n The gas used is: "+ gas); 
	});

	it("should register a Laboratory", async () => {
		const instance = await Authority.deployed();
		let result = await instance.registerLaboratory(laboratory.address, bytes32, bytes32,bytes32 ,bytes32 )
		let gas=result.receipt["cumulativeGasUsed"];
		console.log("\n\n\ CALIBRATION LABORATORY REGISTRATION \n The gas used is: "+ gas); 
	});
	//
	it("should register a Device", async () => {
		const instance = await Authority.deployed();
		let _address = await instance.getManufacturerContractbyEOAAddress(manufacturer.address);
		const _contract= await ManufacturerContract.at(_address);
		const devhash = web3Utils.soliditySha3("DEV_HASH");
		const devhash2 = web3Utils.soliditySha3("DEV_HASH2");
		let result = await _contract.registerDevice(devhash,devhash,{from:manufacturer.address});
		let result2 = await _contract.registerDevice(devhash2,devhash2,{from:manufacturer.address});
		let gas=result.receipt["cumulativeGasUsed"];
		console.log("\n\n\ DEVICE REGISTRATION \n The gas used is: "+ gas); 
	});

	


	it("should accredit a Laboratory", async () => {
		const instance = await Authority.deployed();
		let acc_address = await instance.getAccreditorContractbyEOAAddress(accreditor.address);
		let lab_address = await instance.getLaboratoryContractbyEOAAddress(laboratory.address);
		const acc_contract= await AccreditorContract.at(acc_address);
		const ipfs = web3Utils.soliditySha3("IPFS_HASH");
		const soa = web3Utils.soliditySha3("SOA_HASH");
		let result = await acc_contract.accredit(lab_address,ipfs,vt,soa,{from:accreditor.address});		
		let gas=result.receipt["cumulativeGasUsed"];
		console.log("\n\n\ LABORATORY ACCREDITATION \n The gas used is: "+ gas); 
	});

	it("should register a Laboratory Delegate", async () => {
		const instance = await Authority.deployed();
		let lab_address = await instance.getLaboratoryContractbyEOAAddress(laboratory.address);
		const lab_contract= await LaboratoryContract.at(lab_address);
		let result = await lab_contract.registerDelegate(delegate.address, bytes32, bytes32,bytes32,{from:laboratory.address} )
		let gas=result.receipt["cumulativeGasUsed"];
		console.log("\n\n\ CALIBRATION LABORATORY DELEGATE REGISTRATION \n The gas used is: "+ gas); 
	});

	

	it("should certify a device", async () => {
		const instance = await Authority.deployed();
		let man_address = await instance.getManufacturerContractbyEOAAddress(manufacturer.address);
		let lab_address = await instance.getLaboratoryContractbyEOAAddress(laboratory.address);
		const man_contract= await ManufacturerContract.at(man_address);
		const lab_contract= await LaboratoryContract.at(lab_address);
		const ipfs = web3Utils.soliditySha3("IPFS_HASH");
		const dcc = web3Utils.soliditySha3("DCC_HASH");
		let devID = await man_contract.getDeviceIDbyIndex(0);
		let result = await lab_contract.certify( devID,ipfs,vt,dcc,{from:laboratory.address});		
		let gas=result.receipt["cumulativeGasUsed"];
		console.log("\n\n\ DCC ISSUANCE \n The gas used is: "+ gas); 
	});


	it("should certify a device  by delegate", async () => {
		const instance = await Authority.deployed();
		let man_address = await instance.getManufacturerContractbyEOAAddress(manufacturer.address);
		let lab_address = await instance.getLaboratoryContractbyEOAAddress(laboratory.address);
		const man_contract= await ManufacturerContract.at(man_address);
		const lab_contract= await LaboratoryContract.at(lab_address);
		const ipfs = web3Utils.soliditySha3("IPFS_HASH");
		const dcc = web3Utils.soliditySha3("DCC_HASH");
		let devID = await man_contract.getDeviceIDbyIndex(1);
		let result = await lab_contract.certify( devID,ipfs,vt,dcc,{from:delegate.address});		
		let gas=result.receipt["cumulativeGasUsed"];
		console.log("\n\n\ DCC DELEGATE ISSUANCE \n The gas used is: "+ gas); 
	});


});

/** 
 * SII APPROACH
 **/


// Artifacts

const CredentialRegistry = artifacts.require("CredentialRegistry");
const QualitiyInfrastructure = artifacts.require("QualitiyInfrastructure");
const EthereumDIDRegistry = artifacts.require("EthereumDIDRegistry");


//Typehash

const DELEGATE_TYPEHASH = web3Utils.soliditySha3("Delegate(address issuer, address subject, bytes32 allowed_type_hash, uint256 validFrom, uint256 validTo)");
const VERIFIABLE_CREDENTIAL_TYPEHASH = web3Utils.soliditySha3("VerifiableCredential(address issuer,address subject,bytes32 data,uint256 validFrom,uint256 validTo)");
const EIP712DOMAIN_TYPEHASH = web3Utils.soliditySha3("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
const ID_TYPEHASH = web3Utils.soliditySha3("ID_TYPEHASH");
const DSOA_TYPEHASH = web3Utils.soliditySha3("DSOA_TYPEHASH");
const DEVID_TYPEHASH = web3Utils.soliditySha3("DEVID_TYPEHASH");
const DCC_TYPEHASH = web3Utils.soliditySha3("DCC_TYPEHASH");
const ACCREDITATION_TYPEHASH = web3Utils.soliditySha3("ACCREDITATION_TYPEHASH");

const veriKey = "0x766572694b657900000000000000000000000000000000000000000000000000";
const ipfs = "0x766572694b657900000000000000678000000000000000000000000000000000";
const sleep = seconds => new Promise(resolve => setTimeout(resolve, seconds * 1e3));

//// utility function

// Sign Credential 

function signCredential(credentialHash, issuer) {

	const rsv = ethUtil.ecsign(
		Buffer.from(credentialHash.substring(2, 67), 'hex'),
		Buffer.from(issuer.privateKey, 'hex')
	);
	return ethUtil.toRpcSig(rsv.v, rsv.r, rsv.s);
}

// Format credential

function credential(
	validFrom,
	validTo,
	data,
	allowedType,
	version,
	issuer,
	subject
) {
	return [
		validFrom,
		validTo,
		data,
		allowedType,
		version,
		issuer,
		subject
	]
	;
}
function credentialDelegate(
		validFrom,
		validTo,
		allowedType,
		version,
		issuer,
		subject
	) {
	return [
		validFrom,
		validTo,
		allowedType,
		version,
		issuer,
		subject
	]
}

// Credential hash

async function credentialHash(instance,vc) {
	return await instance.domainHash4(vc);
}
async function credentialHashDelegate(instance,vd){
	return await instance.domainHash1(vd);
}

contract("\n\n\n\n\nSSI Quality Infrastructure", accounts => {

	const vf =1647417846;
	const vt = vf + 31536000;

	const _accounts = {
		admin : {
			address: '0x47adc0faa4f6eb42b499187317949ed99e77ee85',
			privateKey: 'effa7c6816819ee330bc91f1623f3c66a9fed268ecd5b805a002452075b26c0b'
		},
		accreditor : {
			address: '0x4a5a6460d00c4d8c2835a3067f53fb42021d5bb9',
			privateKey: '09288ce70513941f8a859361aeb243c56d5b7a653c1c68374a70385612fe0c2a'
		},
		soaIssuer : {
			address: '0x4222ec932c5a68b80e71f4ddebb069fa02518b8a',
			privateKey: '6ccfcaa51011057276ef4f574a3186c1411d256e4d7731bdf8743f34e608d1d1'
		},
		soaDelegate : {
			address: '0x4ef9e4721bbf02b84d0e73822ee4e26e95076b9d',
			privateKey: '258b7f85027d7b20f74ecfbfca556aad8eff933365fe5b7473355040c09db418'
		},
		dccIssuer : {
			address: '0x2da061c6cfa5c23828e9d8dfbe295a22e8779712',
			privateKey: '60090a13d72f682c03db585bf6c3a296600b5d50598a9ceef3291534dede6bea'
		},
		dccDelegate : {
			address: '0xc1f061d629bbba139dbd07f2eb6a9252a45514c7',
			privateKey: 'e25f43772b0d8f19b0a768dfa779ec2f1422241dfe75293de879dc76607b0405'
		},
		device : {
			address: '0xf8e160be646d2429c64d46fba8e8588b8483dbaf',
			privateKey: '5644e113a0db2e89243741a31dfae322a20c09cc0025826288bf37725464ce34'
		},
		manufacturer : {
			address: '0x74260eb42ffde3c442682c4fb6ceb3e801bbb79a',
			privateKey: 'c053485e0b1e5611a8e9368ca4d9400a62dade4e7abfdaea93f46c382ec82d1d'
		},
		public_administration : {
			address: '0x76393ad6569272385963bc9a135356456bbe3f83',
			privateKey: '862d035b908235f1d0af51713a9e6fc8a1108ac98a77a0be91131d226aa8f4d0'
		},
		delegate : {
			address: '0xae1708b0af10bf1fbee6b4b4220d9453f6007eeb',
			privateKey: '7381f9ee53c41bde0d83e2e69a39f9ddfab74da872d653271a2a9ba050670583'
		}
	}
	const _credential = {
		accreditor_vc : {
			issuer: _accounts.admin,
			subject: _accounts.accreditor,
			validFrom: vf,
			validTo: vt,
			type: ACCREDITATION_TYPEHASH,
			signature: "",
			version: 1,
			data: "0x766572694b657900000000000000000000000000000000000000000000000000"
		},
		soaIssuer_vc : {
			issuer: _accounts.accreditor,
			subject: _accounts.soaIssuer,
			validFrom: vf,
			validTo: vt,
			type: ACCREDITATION_TYPEHASH,
			signature: "",
			version: 1,
			data: "0x766572694b657900000000000000000000000000000000000000000000000000"
		},
		idIssuer_vc : {
			issuer: _accounts.accreditor,
			subject: _accounts.public_administration,
			validFrom: vf,
			validTo: vt,
			type: ACCREDITATION_TYPEHASH,
			signature: "",
			version: 1,
			data: "0x766572694b657900000000000000000000000000000000000000000000000000"
		},
		devIdIssuer_vc : {
			issuer: _accounts.accreditor,
			subject: _accounts.manufacturer,
			validFrom: vf,
			validTo: vt,
			type: ACCREDITATION_TYPEHASH,
			signature: "",
			version: 1,
			data: "0x766572694b657900000000000000000000000000000000000000000000000000"
		},
		id_vc_devID_Issuer : {
			issuer: _accounts.public_administration,
			subject: _accounts.manufacturer,
			validFrom: vf,
			validTo: vt,
			type: ID_TYPEHASH,
			signature: "",
			version: 1,
			data: "0x766572694b657900000000000000000000000000000000000000000000000000"
		},
		id_vc_soa_Issuer : {
			issuer: _accounts.public_administration,
			subject: _accounts.soaIssuer,
			validFrom: vf,
			validTo: vt,
			type: ID_TYPEHASH,
			signature: "",
			version: 1,
			data: "0x766572694b657900000000000000000000000000000000000000000000000000"
		},
		id_vc_dcc_Issuer : {
			issuer: _accounts.public_administration,
			subject: _accounts.dccIssuer,
			validFrom: vf,
			validTo: vt,
			type: ID_TYPEHASH,
			signature: "",
			version: 1,
			data: "0x766572694b657900000000000000000000000000000000000000000000000000"
		},
		devID_vc : {
			issuer: _accounts.manufacturer,
			subject: _accounts.device,
			validFrom: vf,
			validTo:vt,
			type: DEVID_TYPEHASH,
			signature: "",
			version: 1,
			data: "0x766572694b657900000000000000000000000000000000000000000000000000"
		},
		soa_vc : {
			issuer: _accounts.soaIssuer,
			subject: _accounts.dccIssuer,
			validFrom: vf,
			validTo:vt,
			type: DSOA_TYPEHASH,
			signature: "",
			version: 1,
			data: "0x766572694b657900000000000000000000000000000000000000000000000000"
		},
		dcc_vc : {

			issuer: _accounts.dccIssuer,
			subject: _accounts.device,
			validFrom: vf,
			validTo: vt,
			type: DCC_TYPEHASH,
			signature: "",
			version: 1,
			data: "0x766572694b657900000000000000000000000000000000000000000000000000"
		},
		dcc_dc : {

			issuer: _accounts.dccIssuer,
			subject: _accounts.delegate,
			validFrom: vf,
			validTo: vt,
			type: DCC_TYPEHASH,
			signature: "",
			version: 1,
			data: "0x766572694b657900000000000000000000000000000000000000000000000000"
		},
		dcc_vc_2 : {

			issuer: _accounts.dccIssuer,
			subject: _accounts.device,
			validFrom: vf,
			validTo: vt,
			type: DCC_TYPEHASH,
			signature: "",
			version: 1,
			data: "0x766572694b657900000000000000011100000000000000000000000000000000"
		}
	}

	before(async () => {
		const didreg = await EthereumDIDRegistry.deployed()
		didreg.addDelegate(_accounts.soaIssuer.address, veriKey, _accounts.soaDelegate.address, 999999999999999,{ from: _accounts.soaIssuer.address })
		didreg.addDelegate(_accounts.dccIssuer.address, veriKey, _accounts.delegate.address, 999999999999999,{ from: _accounts.dccIssuer.address })
	})

	it("should register an Accreditor", async () => {
		const instance = await QualitiyInfrastructure.deployed()

		const vc= credential(
							_credential.accreditor_vc.validFrom,
							_credential.accreditor_vc.validTo,
							_credential.accreditor_vc.data,
							_credential.accreditor_vc.type,
							1,
							_credential.accreditor_vc.issuer.address,
							_credential.accreditor_vc.subject.address
							)
		let digest= await credentialHash(instance,vc)
		let signature= await signCredential(digest, _credential.accreditor_vc.issuer)
		let result =(await instance.registerAccreditorIssuer(vc,ipfs,signature));
		let log=result.logs[1]
		let gas=result.receipt["cumulativeGasUsed"]
		
		console.log("\n\n\GOVERNMENT REGISTRATION \n The gas used is: "+ gas); 
	});

	it("should register an ID Issuer", async () => {
		const instance = await QualitiyInfrastructure.deployed()


		const vc= credential(
			                _credential.idIssuer_vc.validFrom,
							_credential.idIssuer_vc.validTo,
							_credential.idIssuer_vc.data,
							_credential.idIssuer_vc.type,
							1,
							_credential.idIssuer_vc.issuer.address,
							_credential.idIssuer_vc.subject.address
							)
		let digest= await credentialHash(instance,vc)
		let signature= await signCredential(digest, _credential.idIssuer_vc.issuer)
		let result =(await instance.registerIDIssuer(vc,ipfs,signature,{ from: _credential.idIssuer_vc.issuer.address }));
		let gas=result.receipt["cumulativeGasUsed"]
		
		console.log("\n\n\ PUBLIC ADMINISTRATION REGISTRATION \n The gas used is: "+ gas); 
	});

	it("should register an DEVID Issuer", async () => {
		const instance = await QualitiyInfrastructure.deployed()

		const id_vc= credential(
			_credential.id_vc_devID_Issuer.validFrom,
			_credential.id_vc_devID_Issuer.validTo,
			_credential.id_vc_devID_Issuer.data,
			_credential.id_vc_devID_Issuer.type,
			1,
			_credential.id_vc_devID_Issuer.issuer.address,
			_credential.id_vc_devID_Issuer.subject.address
					)
		let digest_= await credentialHash(instance,id_vc)
		let signature_= await signCredential(digest_, _credential.id_vc_devID_Issuer.issuer)
		let result_ =(await instance.registerCredential(id_vc,ipfs,signature_,{ from: _credential.id_vc_devID_Issuer.issuer.address }));
		let gas_id=result_.receipt["cumulativeGasUsed"]


		const vc= credential(
			                _credential.devIdIssuer_vc.validFrom,
							_credential.devIdIssuer_vc.validTo,
							_credential.devIdIssuer_vc.data,
							_credential.devIdIssuer_vc.type,
							1,
							_credential.devIdIssuer_vc.issuer.address,
							_credential.devIdIssuer_vc.subject.address
							)
		let digest= await credentialHash(instance,vc)
		let signature= await signCredential(digest, _credential.devIdIssuer_vc.issuer)
		let result =(await instance.registerDEVIDIssuer(vc,ipfs,signature,{ from: _credential.devIdIssuer_vc.issuer.address }));
		let log=result.logs[1]
		let gas=result.receipt["cumulativeGasUsed"]
	
		console.log("\n\n\ MANUFACTURER REGISTRATION \n The gas used for ID registration is: "+ gas_id +"\n The gas used for credential is: "+ gas); 
	});

	it("should register an DSOA Accreditor", async () => {
		const instance = await QualitiyInfrastructure.deployed()

		const id_vc= credential(
			_credential.id_vc_soa_Issuer.validFrom,
			_credential.id_vc_soa_Issuer.validTo,
			_credential.id_vc_soa_Issuer.data,
			_credential.id_vc_soa_Issuer.type,
			1,
			_credential.id_vc_soa_Issuer.issuer.address,
			_credential.id_vc_soa_Issuer.subject.address
					)
		let digest_= await credentialHash(instance,id_vc)
		let signature_= await signCredential(digest_, _credential.id_vc_soa_Issuer.issuer)
		let result_ =(await instance.registerCredential(id_vc,ipfs,signature_,{ from: _credential.id_vc_soa_Issuer.issuer.address }));
		let gas_id=result_.receipt["cumulativeGasUsed"]


		const vc= credential(
			_credential.soaIssuer_vc.validFrom,
			_credential.soaIssuer_vc.validTo,
			_credential.soaIssuer_vc.data,
			_credential.soaIssuer_vc.type,
			1,
			_credential.soaIssuer_vc.issuer.address,
			_credential.soaIssuer_vc.subject.address
					)
		let digest= await credentialHash(instance,vc)
		let signature= await signCredential(digest, _credential.soaIssuer_vc.issuer)
		let result =(await instance.registerDSOAIssuer(vc,ipfs,signature,{ from: _credential.soaIssuer_vc.issuer.address }));
		let log=result.logs[1]
		let gas=result.receipt["cumulativeGasUsed"]

		console.log("\n\n\ ACCREDITATION BODY REGISTRATION \n The gas used for ID registration is: "+ gas_id +"\n The gas used for credential is: "+ gas); 
	});

	it("should register an DSOA CERTIFICTE and hence accredit a DCC Issuer", async () => {
		const instance = await QualitiyInfrastructure.deployed()

		const id_vc= credential(
			_credential.id_vc_dcc_Issuer.validFrom,
			_credential.id_vc_dcc_Issuer.validTo,
			_credential.id_vc_dcc_Issuer.data,
			_credential.id_vc_dcc_Issuer.type,
			1,
			_credential.id_vc_dcc_Issuer.issuer.address,
			_credential.id_vc_dcc_Issuer.subject.address
					)
		let digest_= await credentialHash(instance,id_vc)
		let signature_= await signCredential(digest_, _credential.id_vc_dcc_Issuer.issuer)
		let result_ =(await instance.registerCredential(id_vc,ipfs,signature_,{ from: _credential.id_vc_dcc_Issuer.issuer.address }));
		let gas_id=result_.receipt["cumulativeGasUsed"]

		const vc= credential(
							_credential.soa_vc.validFrom,
							_credential.soa_vc.validTo,
							_credential.soa_vc.data,
							_credential.soa_vc.type,
							1,
							_credential.soa_vc.issuer.address,
							_credential.soa_vc.subject.address
							)
		let digest= await credentialHash(instance,vc)
		let signature= await signCredential(digest, _credential.soa_vc.issuer)
		let result =(await instance.registerDSOACredential(vc,ipfs,signature,{ from: _credential.soa_vc.issuer.address }));
		let log=result.logs[1]
		let gas=result.receipt["cumulativeGasUsed"]
		
		console.log("\n\n\ CALIBRATION LABORATORY REGISTRATION \n The gas used for ID registration is: "+ gas_id +"\n The gas used for credential is: "+ gas); 
	});

	it("should register a DEVID CERTIFICTE ", async () => {
		const instance = await QualitiyInfrastructure.deployed()


		const vc= credential(
							_credential.devID_vc.validFrom,
							_credential.devID_vc.validTo,
							_credential.devID_vc.data,
							_credential.devID_vc.type,
							1,
							_credential.devID_vc.issuer.address,
							_credential.devID_vc.subject.address
							)
		
		let digest= await credentialHash(instance,vc)
		let signature= await signCredential(digest, _credential.devID_vc.issuer)
		let result =(await instance.registerCredential(vc,ipfs,signature,{ from: _credential.devID_vc.issuer.address }));
		let log=result.logs[1]
		let gas=result.receipt["cumulativeGasUsed"]
		
		console.log("\n\n\ DEVICE REGISTRATION \n The gas used is: "+ gas); 
	});

	it("should register an DCC CERTIFICTE ", async () => {
		const instance = await QualitiyInfrastructure.deployed()


		const vc= credential(
							_credential.dcc_vc.validFrom,
							_credential.dcc_vc.validTo,
							_credential.dcc_vc.data,
							_credential.dcc_vc.type,
							1,
							_credential.dcc_vc.issuer.address,
							_credential.dcc_vc.subject.address
							)
		let digest= await credentialHash(instance,vc)
		let signature= await signCredential(digest, _credential.dcc_vc.issuer)
		let result =(await instance.registerCredential(vc,ipfs,signature,{ from: _credential.dcc_vc.issuer.address }));
		let log=result.logs[1]
		let gas=result.receipt["cumulativeGasUsed"]
		
		console.log("\n\n\ DCC CERTIFICATE REGISTRATION \n The gas used is: "+ gas); 
	});

	it("should register an DCC delegate ", async () => {
		const instance = await QualitiyInfrastructure.deployed()


		const vc= credentialDelegate(
							_credential.dcc_dc.validFrom,
							_credential.dcc_dc.validTo,
							_credential.dcc_dc.type,
							1,
							_credential.dcc_dc.issuer.address,
							_credential.dcc_dc.subject.address
							)
		let digest= await credentialHashDelegate(instance,vc)
		let signature= await signCredential(digest, _credential.dcc_dc.issuer)
		let result =(await instance.registerDelegate(vc,ipfs,signature,{ from: _credential.dcc_dc.issuer.address }));
		let log=result.logs[1]
		let gas=result.receipt["cumulativeGasUsed"]
		
		console.log("\n\n\ DCC DELEGATE REGISTRATION \n The gas used is: "+ gas); 
	});

	it("should register a DELEGATED DCC CERTIFICTE ", async () => {
		const instance = await QualitiyInfrastructure.deployed()


		const vc= credential(
							_credential.dcc_vc_2.validFrom,
							_credential.dcc_vc_2.validTo,
							_credential.dcc_vc_2.data,
							_credential.dcc_vc_2.type,
							1,
							_credential.dcc_vc_2.issuer.address,
							_credential.dcc_vc_2.subject.address
							)
		let digest= await credentialHash(instance,vc)
		let signature= await signCredential(digest, _accounts.delegate)
		let result =(await instance.registerCredential(vc,ipfs,signature,{ from: _accounts.delegate.address }));
		let log=result.logs[1]
		let gas=result.receipt["cumulativeGasUsed"]
		
		console.log("\n\n\ DCC CERTIFICATE REGISTRATION BY DELEGATE\n The gas used is: "+ gas); 
	});

	
});