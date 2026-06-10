// Deploys IdentityRegistry to the configured network.
//
//   TESSERA_EVM_RPC       — JSON-RPC endpoint
//   TESSERA_EVM_KEY       — deployer private key (becomes the initial authority unless overridden)
//   TESSERA_EVM_AUTHORITY — optional explicit issuer-registry authority address
//
// Usage: npm run deploy:bnbtestnet
const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  const authority = process.env.TESSERA_EVM_AUTHORITY || deployer.address;

  console.log(`Deployer:  ${deployer.address}`);
  console.log(`Authority: ${authority}`);

  const Factory = await ethers.getContractFactory("IdentityRegistry");
  const registry = await Factory.deploy(authority);
  await registry.waitForDeployment();

  const address = await registry.getAddress();
  console.log(`IdentityRegistry deployed at: ${address}`);
  console.log("Set TESSERA_EVM_REGISTRY to this address for the C# adapter / integration tests.");
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
