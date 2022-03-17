const Migrations = artifacts.require("Migrations");
const AuthorityContract = artifacts.require("AuthorityContract");
const ManufacturerFactory = artifacts.require("ManufacturerFactory");
const LaboratoryFactory = artifacts.require("LaboratoryFactory");
const AccreditorFactory = artifacts.require("AccreditorFactory");
const CredentialRegistry = artifacts.require("CredentialRegistry");
const QualitiyInfrastructure = artifacts.require("QualitiyInfrastructure");
const EthereumDIDRegistry = artifacts.require("EthereumDIDRegistry");

// first credential parameter

const from =1647417846;
const to =  1678953846;
const ipfs="0x766572694b657900000000000000678000000000000000000000000000000000";
const digest="0x4e38b29a64a2c83ffa8e26fac63f0705971a3a817158bd1f6c5707e269b5d8ac";


module.exports = async function (deployer) {
  
  // Naive approach
  
  await deployer.deploy(Migrations);
  const Authority = await deployer.deploy(AuthorityContract);
  const mf = await deployer.deploy(ManufacturerFactory);
  const lf = await deployer.deploy(LaboratoryFactory);
  const af = await deployer.deploy(AccreditorFactory);
  await Authority.setUpFactory(mf.address,lf.address,af.address);
  await af.transferOwnership(Authority.address);
  await lf.transferOwnership(Authority.address);
  await mf.transferOwnership(Authority.address);

  // SSI approach
  
  await deployer.deploy(Migrations);
  const registry = await deployer.deploy(CredentialRegistry);
  const DIDregistry = await deployer.deploy(EthereumDIDRegistry);
  const verifier = await deployer.deploy(QualitiyInfrastructure, registry.address,DIDregistry.address);
  await registry.grantRole( await registry.ISSUER_ROLE(), verifier.address );
  await verifier.InitializeAdmin(digest,from,to,ipfs);
  
};
