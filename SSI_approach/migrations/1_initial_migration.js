const Migrations = artifacts.require("Migrations");
const CredentialRegistry = artifacts.require("CredentialRegistry");
const ClaimsVerifier = artifacts.require("ClaimsVerifier");
const EthereumDIDRegistry = artifacts.require("EthereumDIDRegistry");

module.exports = async function (deployer) {
  await deployer.deploy(Migrations);
  const registry = await deployer.deploy(CredentialRegistry);
  const DIDregistry = await deployer.deploy(EthereumDIDRegistry);
  const verifier = await deployer.deploy(ClaimsVerifier, registry.address,DIDregistry.address);
  await registry.grantRole( await registry.ISSUER_ROLE(), verifier.address );
};
