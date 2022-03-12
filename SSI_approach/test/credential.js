const crypto = require( 'crypto' );
const moment = require( "moment" );
const web3Abi = require( "web3-eth-abi" );
const web3Utils = require( "web3-utils" );
const ethUtil = require( "ethereumjs-util" );
const console = require('console');

// Artifacts

	const CredentialRegistry = artifacts.require( "CredentialRegistry" );
	const ClaimsVerifier = artifacts.require( "ClaimsVerifier" );
	const EthereumDIDRegistry = artifacts.require("EthereumDIDRegistry");

//Typehash

	const DELEGATE_TYPEHASH = web3Utils.soliditySha3("Delegate(address issuer, address subject, bytes32 allowed_type_hash, uint256 validFrom, uint256 validTo)");
	const VERIFIABLE_DELEGATE_TYPEHASH = web3Utils.soliditySha3(web3Utils.encodePacked("VerifiableDelegate(Delegate delegate, uint8 v, bytes32 r, bytes32 s)", DELEGATE_TYPEHASH));
	const VERIFIABLE_CREDENTIAL_TYPEHASH = web3Utils.soliditySha3( "VerifiableCredential(address issuer,address subject,bytes32 data,uint256 validFrom,uint256 validTo)" );
	const DELEGATED_VERIFIABLE_CREDENTIAL_TYPEHASH = web3Utils.soliditySha3( web3Utils.encodePacked("VerifiableCredential(VerifiableDelegate issuer,address subject,bytes32 data,uint256 validFrom,uint256 validTo)",VERIFIABLE_DELEGATE_TYPEHASH))
	const EIP712DOMAIN_TYPEHASH = web3Utils.soliditySha3( "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)" );

	const sleep = seconds => new Promise( resolve => setTimeout( resolve, seconds * 1e3 ) );

// utility function

	// Hash in hex

		function sha256( data ) {
			const hashFn = crypto.createHash( 'sha256' );
			hashFn.update( data );
			return hashFn.digest( 'hex' );
		}

	// Credential hash

		function getCredentialHash( vc, issuer, claimsVerifierContractAddress ) {
			const hashDiplomaHex = `0x${sha256( JSON.stringify( vc.credentialSubject ) )}`;

			const encodeEIP712Domain = web3Abi.encodeParameters(
				['bytes32', 'bytes32', 'bytes32', 'uint256', 'address'],
				[EIP712DOMAIN_TYPEHASH, web3Utils.sha3( "EIP712Domain" ), web3Utils.sha3( "1" ), 648529, claimsVerifierContractAddress]
			);
			const hashEIP712Domain = web3Utils.soliditySha3( encodeEIP712Domain );

			const validFrom = new Date( vc.issuanceDate ).getTime();
			const validTo = new Date( vc.expirationDate ).getTime();
			const subjectAddress = vc.credentialSubject.id.split( ':' ).slice( -1 )[0];
			const encodeHashCredential = web3Abi.encodeParameters(
				['bytes32', 'address', 'address', 'bytes32', 'uint256', 'uint256'],
				[VERIFIABLE_CREDENTIAL_TYPEHASH, issuer.address, subjectAddress, hashDiplomaHex, Math.round( validFrom / 1000 ), Math.round( validTo / 1000 )]
			);
			const hashCredential = web3Utils.soliditySha3( encodeHashCredential );

			const encodedCredentialHash = web3Abi.encodeParameters( ['bytes32', 'bytes32'], [hashEIP712Domain, hashCredential.toString( 16 )] );
			return web3Utils.soliditySha3( '0x1901'.toString( 16 ) + encodedCredentialHash.substring( 2, 131 ) );
		}

	// Sign Credential 

		function signCredential( credentialHash, issuer ) {
			
			const rsv = ethUtil.ecsign(
				Buffer.from( credentialHash.substring( 2, 67 ), 'hex' ),
				Buffer.from( issuer.privateKey, 'hex' )
			);
			return ethUtil.toRpcSig( rsv.v, rsv.r, rsv.s );
		}


contract( "Verifiable Credentials", accounts => {

	const subject = accounts[1];
	const issuer = {
		address: '0x47adc0faa4f6eb42b499187317949ed99e77ee85',
		privateKey: 'effa7c6816819ee330bc91f1623f3c66a9fed268ecd5b805a002452075b26c0b'
	};
	const delegates = [{
		address: '0x4a5a6460d00c4d8c2835a3067f53fb42021d5bb9',
		privateKey: '09288ce70513941f8a859361aeb243c56d5b7a653c1c68374a70385612fe0c2a'
	}, {
		address: '0x4222ec932c5a68b80e71f4ddebb069fa02518b8a',
		privateKey: '6ccfcaa51011057276ef4f574a3186c1411d256e4d7731bdf8743f34e608d1d1'
	}]
	const vc = {
		"@context": "https://www.w3.org/2018/credentials/v1",
		id: "73bde252-cb3e-44ab-94f9-eba6a8a2f28d",
		type: "VerifiableCredential",
		issuer: `did:lac:main:${issuer.address}`,
		issuanceDate: moment().toISOString(),
		expirationDate: moment().add( 1, 'years' ).toISOString(),
		credentialSubject: {
			id: `did:lac:main:${subject}`,
			data: 'test'
		},
		proof: []
	}

	const delegate_vc = [{
		"@context": "https://www.w3.org/2018/credentials/v1",
		id: "73bde252-cb3e-44ab-94f9-eba6a8a2f28d",
		type: "VerifiableDelegate,Delegate",
		issuer: `did:lac:main:${issuer.address}`,
		issuanceDate: moment().toISOString(),
		expirationDate: moment().add( 1, 'years' ).toISOString(),
		credentialSubject: {
			id: `did:lac:main:${delegates[0].address}`,
			data: 'test'
		},
		proof: [
			{
				id: "did:lac:main:${issuer.address}",
				type: "EcdsaSecp256k1Signature2019",
				proofPurpose: "assertionMethod",
				verificationMethod: `${issuer.address}#vm-0`,
				domain:"",
				proofValue: "",

			}
		]
	},
	{
		"@context": "https://www.w3.org/2018/credentials/v1",
		id: "73bde252-cb3e-44ab-94f9-eba6a8a2f28a",
		type: "VerifiableCredential",
		issuer: `did:lac:main:${delegates[0].address}`,
		issuanceDate: moment().toISOString(),
		expirationDate: moment().add( 1, 'years' ).toISOString(),
		credentialSubject: {
			id: `did:lac:main:${subject}`,
			data: 'test'
		},
		proof: [
			{
			    id: "did:lac:main:${delegates[0].address}",
				type: "EcdsaSecp256k1Signature2019",
				proofPurpose: "assertionMethod",
				verificationMethod: `${issuer.address}#vm-0`,
				domain:"",
				proofValue: ""
			}
		]
	}
]

	before( async() => {
		
		const instance = await ClaimsVerifier.deployed()
		await instance.grantRole( await instance.ISSUER_ROLE(), issuer.address );
	} )

	it( "should register a VC", async() => {
		const instance = await ClaimsVerifier.deployed()
		

		const credentialHash = getCredentialHash( vc, issuer, instance.address );
		//console.log(credentialHash.substring( 2, 67 ));
		const signature = await signCredential( credentialHash, issuer );
		
		const tx = await instance.methods['registerCredential(address,bytes32,uint256,uint256,bytes)']
			( subject, credentialHash,
			Math.round( moment( vc.issuanceDate ).valueOf() / 1000 ),
			Math.round( moment( vc.expirationDate ).valueOf() / 1000 ),
			signature, { from: issuer.address } );
		
		
		vc.proof.push( {
			id: vc.issuer,
			type: "EcdsaSecp256k1Signature2019",
			proofPurpose: "assertionMethod",
			verificationMethod: `${vc.issuer}#vm-0`,
			domain: instance.address,
			proofValue: signature
		} );
		console.log("should register a VC, gas:",tx.receipt.gasUsed);
		await sleep( 1 );
		
		return true;
	} );

	/*it( "should verify a VC", async() => {
		const instance = await ClaimsVerifier.deployed()
		// console.log( vc );

		const data = `0x${sha256( JSON.stringify( vc.credentialSubject ) )}`;
		const rsv = ethUtil.fromRpcSig( vc.proof[0].proofValue );
		const result = await instance.verifyCredential( [
			vc.issuer.replace( 'did:lac:main:', '' ),
			vc.credentialSubject.id.replace( 'did:lac:main:', '' ),
			data,
			Math.round( moment( vc.issuanceDate ).valueOf() / 1000 ),
			Math.round( moment( vc.expirationDate ).valueOf() / 1000 )
		], rsv.v, rsv.r, rsv.s );

		const credentialExists = result[0];
		const isNotRevoked = result[1];
		const issuerSignatureValid = result[2];
		const additionalSigners = result[3];
		const isNotExpired = result[4];

		assert.equal( credentialExists, true );
		assert.equal( isNotRevoked, true );
		assert.equal( issuerSignatureValid, true );
		assert.equal( additionalSigners, true );
		assert.equal( isNotExpired, true );
	} );

	it( "should revoke the credential", async() => {
		const instance = await ClaimsVerifier.deployed()
		const registry = await CredentialRegistry.deployed()

		const credentialHash = getCredentialHash( vc, issuer, instance.address );

		const tx = await registry.revokeCredential( credentialHash );
		console.log("should revoke the credential, gas:",tx.receipt.gasUsed);
		assert.equal( tx.receipt.status, true );
	} );

	it( "should fail the verification process due credential status", async() => {
		const instance = await ClaimsVerifier.deployed()

		const data = `0x${sha256( JSON.stringify( vc.credentialSubject ) )}`;
		const rsv = ethUtil.fromRpcSig( vc.proof[0].proofValue );
		const result = await instance.verifyCredential( [
			vc.issuer.replace( 'did:lac:main:', '' ),
			vc.credentialSubject.id.replace( 'did:lac:main:', '' ),
			data,
			Math.round( moment( vc.issuanceDate ).valueOf() / 1000 ),
			Math.round( moment( vc.expirationDate ).valueOf() / 1000 )
		], rsv.v, rsv.r, rsv.s );

		const isNotRevoked = result[1];

		assert.equal( isNotRevoked, false );
	} );

	it( "should verify credential status using the CredentialRegistry", async() => {
		const instance = await ClaimsVerifier.deployed()
		const registry = await CredentialRegistry.deployed()

		const credentialHash = getCredentialHash( vc, issuer, instance.address );

		const result = await registry.status( issuer.address, credentialHash );

		assert.equal( result, false );
	} );*/
} );