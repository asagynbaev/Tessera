// Deploys IdentityRegistry + Allowlist to the configured network and records their
// addresses in deployed.<network>.json — the testnet counterpart of deploy-local.js.
//
//   TESSERA_EVM_RPC       — JSON-RPC endpoint
//   TESSERA_EVM_KEY       — deployer private key (becomes the initial authority unless overridden)
//   TESSERA_EVM_AUTHORITY — optional explicit issuer-registry authority address
//
// The deployer becomes the IdentityRegistry authority and the Allowlist owner/agent, which is
// exactly what the testnet smoke suite (EvmTestnetSmokeTests + EvmAllowlistSmokeTests) needs:
// one signing key both registers DIDs and flips the allowlist.
//
// Usage: npm run deploy:bnbtestnet   (or: hardhat run scripts/deploy.js --network <name>)
const { ethers, network } = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const [deployer] = await ethers.getSigners();
  const authority = process.env.TESSERA_EVM_AUTHORITY || deployer.address;
  const chainId = Number((await ethers.provider.getNetwork()).chainId);

  console.log(`Network:   ${network.name} (chainId ${chainId})`);
  console.log(`Deployer:  ${deployer.address}`);
  console.log(`Authority: ${authority}`);

  const Registry = await ethers.getContractFactory("IdentityRegistry");
  const registry = await Registry.deploy(authority);
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();

  const Allowlist = await ethers.getContractFactory("Allowlist");
  const allowlist = await Allowlist.deploy();
  await allowlist.waitForDeployment();
  const allowlistAddr = await allowlist.getAddress();

  const out = {
    chainId,
    registry: registryAddr,
    allowlist: allowlistAddr,
    deployer: deployer.address,
    authority,
  };

  const file = path.join(__dirname, "..", `deployed.${network.name}.json`);
  fs.writeFileSync(file, JSON.stringify(out, null, 2));

  console.log(`\nIdentityRegistry deployed at: ${registryAddr}`);
  console.log(`Allowlist deployed at:        ${allowlistAddr}`);
  console.log(`Wrote ${file}`);

  // Ready-to-source env for the C# smoke suite (mirrors .env.local.example).
  console.log("\n# Export these for src/Tessera.Chains.Evm.Tests:");
  console.log(`export TESSERA_EVM_RPC=${process.env.TESSERA_EVM_RPC || "<rpc-url>"}`);
  console.log(`export TESSERA_EVM_CHAINID=${chainId}`);
  console.log(`export TESSERA_EVM_REGISTRY=${registryAddr}`);
  console.log(`export TESSERA_EVM_ALLOWLIST=${allowlistAddr}`);
  console.log("# (TESSERA_EVM_KEY = the same funded deployer key you used here)");
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
