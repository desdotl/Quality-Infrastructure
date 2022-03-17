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
		let result = await _contract.registerDevice(devhash,devhash,{from:manufacturer.address});
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

	it("should certify a device", async () => {
		const instance = await Authority.deployed();
		let man_address = await instance.getManufacturerContractbyEOAAddress(manufacturer.address);
		let lab_address = await instance.getLaboratoryContractbyEOAAddress(laboratory.address);
		const man_contract= await ManufacturerContract.at(man_address);
		const lab_contract= await LaboratoryContract.at(lab_address);
		const ipfs = web3Utils.soliditySha3("IPFS_HASH");
		const dcc = web3Utils.soliditySha3("DCC_HASH");
		const dev1 = web3Utils.soliditySha3("DEV1_HASH");
		const dev2 = web3Utils.soliditySha3("DEV2_HASH");
		let devID = await man_contract.getDeviceIDbyIndex(0);
		let result = await lab_contract.certify( devID,ipfs,vt,dcc,{from:laboratory.address});		
		let gas=result.receipt["cumulativeGasUsed"];
		console.log("\n\n\ DCC ISSUANCE \n The gas used is: "+ gas); 
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
const VERIFIABLE_DELEGATE_TYPEHASH = web3Utils.soliditySha3(web3Utils.encodePacked("VerifiableDelegate(Delegate delegate, uint8 v, bytes32 r, bytes32 s)", DELEGATE_TYPEHASH));
const VERIFIABLE_CREDENTIAL_TYPEHASH = web3Utils.soliditySha3("VerifiableCredential(address issuer,address subject,bytes32 data,uint256 validFrom,uint256 validTo)");
const DELEGATED_VERIFIABLE_CREDENTIAL_TYPEHASH = web3Utils.soliditySha3(web3Utils.encodePacked("VerifiableCredential(VerifiableDelegate issuer,address subject,bytes32 data,uint256 validFrom,uint256 validTo)", VERIFIABLE_DELEGATE_TYPEHASH));
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
		data,
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

contract("SSI Quality Infrastructure", accounts => {


	const admin = {
		address: '0x47adc0faa4f6eb42b499187317949ed99e77ee85',
		privateKey: 'effa7c6816819ee330bc91f1623f3c66a9fed268ecd5b805a002452075b26c0b'
	};
	const accreditor = {
		address: '0x4a5a6460d00c4d8c2835a3067f53fb42021d5bb9',
		privateKey: '09288ce70513941f8a859361aeb243c56d5b7a653c1c68374a70385612fe0c2a'
	};
	const soaIssuer = {
		address: '0x4222ec932c5a68b80e71f4ddebb069fa02518b8a',
		privateKey: '6ccfcaa51011057276ef4f574a3186c1411d256e4d7731bdf8743f34e608d1d1'
	};
	const soaDelegate = {
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

	const vf =1647417846;
	const vt = vf + 31536000;



	const accreditor_vc = {
		issuer: admin,
		subject: accreditor,
		validFrom: vf,
		validTo: vt,
		type: ACCREDITATION_TYPEHASH,
		signature: "",
		version: 1,
		data: "0x766572694b657900000000000000000000000000000000000000000000000000"

	};
	const soaIssuer_vc = {
		issuer: accreditor,
		subject: soaIssuer,
		validFrom: vf,
		validTo: vt,
		type: ACCREDITATION_TYPEHASH,
		signature: "",
		version: 1,
		data: "0x766572694b657900000000000000000000000000000000000000000000000000"
	};
	const soa_vc = {

		issuer: soaIssuer,
		subject: dccIssuer,
		validFrom: vf,
		validTo:vt,
		type: DSOA_TYPEHASH,
		signature: "",
		version: 1,
		data: "0x766572694b657900000000000000000000000000000000000000000000000000"
	}
	const dcc_vc = {

		issuer: dccIssuer,
		subject: device,
		validFrom: vf,
		validTo: vt,
		type: DCC_TYPEHASH,
		signature: "",
		version: 1,
		data: "0x766572694b657900000000000000000000000000000000000000000000000000"
	}
	

	before(async () => {
		const didreg = await EthereumDIDRegistry.deployed()
		didreg.addDelegate(soaIssuer.address, veriKey, soaDelegate.address, 999999999999999,{ from: soaIssuer.address })
		didreg.addDelegate(dccIssuer.address, veriKey, dccDelegate.address, 999999999999999,{ from: dccIssuer.address })
	})

	it("should register an Accreditor", async () => {
		const instance = await QualitiyInfrastructure.deployed()


		const vc= credential(accreditor_vc.validFrom,
							accreditor_vc.validTo,
							accreditor_vc.data,
							accreditor_vc.type,
							1,
							accreditor_vc.issuer.address,
							accreditor_vc.subject.address
							)
		let digest= await credentialHash(instance,vc)
		let signature= await signCredential(digest, accreditor_vc.issuer)
		let result =(await instance.registerAccreditorIssuer(vc,ipfs,signature));
		let log=result.logs[1]
		let gas=result.receipt["cumulativeGasUsed"]
		
		assert.equal( log.args["issuer"].toLowerCase(), accreditor_vc.subject.address,"The accreditor has not been register as issuer");
		assert.equal( log.args["typeID"], accreditor_vc.type,"The accreditation type is not correct");
		console.log("\n\n\  GOVERNMENT REGISTRATION \n The gas used is: "+ gas); 
	});

	it("should register an DSOA Accreditor", async () => {
		const instance = await QualitiyInfrastructure.deployed()


		const vc= credential(soaIssuer_vc.validFrom,
							soaIssuer_vc.validTo,
							soaIssuer_vc.data,
							soaIssuer_vc.type,
							1,
							soaIssuer_vc.issuer.address,
							soaIssuer_vc.subject.address
							)
		let digest= await credentialHash(instance,vc)
		let signature= await signCredential(digest, soaIssuer_vc.issuer)
		let result =(await instance.registerDSOAIssuer(vc,ipfs,signature,{ from: soaIssuer_vc.issuer.address }));
		let log=result.logs[1]
		let gas=result.receipt["cumulativeGasUsed"]
		
		assert.equal( log.args["issuer"].toLowerCase(), soaIssuer_vc.subject.address,"The dsoa accreditor has not been register as issuer");
		assert.equal( log.args["typeID"],DSOA_TYPEHASH ,"The accreditation type is not correct");
		console.log("\n\n\ ACCREDITATION BODY REGISTRATION \n The gas used is: "+ gas); 
	});

	it("should register an DSOA CERTIFICTE and hence accredit a DCC Issuer", async () => {
		const instance = await QualitiyInfrastructure.deployed()


		const vc= credential(
							soa_vc.validFrom,
							soa_vc.validTo,
							soa_vc.data,
							soa_vc.type,
							1,
							soa_vc.issuer.address,
							soa_vc.subject.address
							)
		let digest= await credentialHash(instance,vc)
		let signature= await signCredential(digest, soa_vc.issuer)
		let result =(await instance.registerDSOACredential(vc,ipfs,signature,{ from: soa_vc.issuer.address }));
		let log=result.logs[1]
		let gas=result.receipt["cumulativeGasUsed"]
		
		assert.equal( log.args["issuer"].toLowerCase(), soa_vc.subject.address,"The laboratory has not been register as issuer");
		assert.equal( log.args["typeID"], DCC_TYPEHASH,"The accreditation type is not correct");
		console.log("\n\n\ CALIBRATION LABORATORI REGISTRATION \n The gas used is: "+ gas); 
	});

	it("should register an DCC CERTIFICTE ", async () => {
		const instance = await QualitiyInfrastructure.deployed()


		const vc= credential(
							dcc_vc.validFrom,
							dcc_vc.validTo,
							dcc_vc.data,
							dcc_vc.type,
							1,
							dcc_vc.issuer.address,
							dcc_vc.subject.address
							)
		let digest= await credentialHash(instance,vc)
		let signature= await signCredential(digest, dcc_vc.issuer)
		let result =(await instance.registerDSOACredential(vc,ipfs,signature,{ from: dcc_vc.issuer.address }));
		let log=result.logs[1]
		let gas=result.receipt["cumulativeGasUsed"]
		
		console.log("\n\n\ DCC CERTIFICATE REGISTRATION \n The gas used is: "+ gas); 
	});

	
});