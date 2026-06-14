// Deploys IdentityRegistry + Allowlist to a local node (e.g. `npx hardhat node`) and writes
// their addresses to deployed.local.json so the C# EVM smoke tests can pick them up.
//
// The deployer becomes the IdentityRegistry authority and the Allowlist owner/agent, which is
// exactly what the smoke tests need (same signing key flips the allowlist).
//
// Usage: npx hardhat run scripts/deploy-local.js --network localhost
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log(`Deployer: ${deployer.address}`);

  const Registry = await ethers.getContractFactory("IdentityRegistry");
  const registry = await Registry.deploy(deployer.address);
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();

  const Allowlist = await ethers.getContractFactory("Allowlist");
  const allowlist = await Allowlist.deploy();
  await allowlist.waitForDeployment();
  const allowlistAddr = await allowlist.getAddress();

  const out = {
    chainId: Number((await ethers.provider.getNetwork()).chainId),
    registry: registryAddr,
    allowlist: allowlistAddr,
    deployer: deployer.address,
  };

  const file = path.join(__dirname, "..", "deployed.local.json");
  fs.writeFileSync(file, JSON.stringify(out, null, 2));

  console.log(`IdentityRegistry: ${registryAddr}`);
  console.log(`Allowlist:        ${allowlistAddr}`);
  console.log(`Wrote ${file}`);
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
