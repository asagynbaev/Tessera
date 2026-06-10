// Copies the compiled ABI(s) into chains/evm/abi/ so they are checked into the repo
// as the stable contract interface the C# adapter and integration tests target.
// Run after `hardhat compile`.
const fs = require("fs");
const path = require("path");

const ARTIFACTS = path.join(__dirname, "..", "artifacts", "contracts");
const OUT = path.join(__dirname, "..", "abi");

const CONTRACTS = ["IdentityRegistry", "Allowlist", "PermissionedToken"];

fs.mkdirSync(OUT, { recursive: true });

for (const name of CONTRACTS) {
  const artifactPath = path.join(ARTIFACTS, `${name}.sol`, `${name}.json`);
  if (!fs.existsSync(artifactPath)) {
    console.warn(`skip ${name}: ${artifactPath} not found (compile first)`);
    continue;
  }
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  fs.writeFileSync(
    path.join(OUT, `${name}.abi.json`),
    JSON.stringify(artifact.abi, null, 2) + "\n"
  );
  console.log(`wrote abi/${name}.abi.json`);
}
