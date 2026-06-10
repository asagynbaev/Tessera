require("@nomicfoundation/hardhat-toolbox");

/**
 * Hardhat config for the Tessera EVM IdentityRegistry.
 *
 * Networks are configured from environment variables so no secrets live in the repo:
 *   TESSERA_EVM_RPC  — JSON-RPC endpoint (e.g. a BNB Chain testnet RPC)
 *   TESSERA_EVM_KEY  — deployer private key (hex, with or without 0x)
 *
 * BNB Chain testnet chainId is 97; mainnet is 56. The contract itself is
 * network-agnostic — chainId/RPC are pure configuration, never baked in.
 */
const RPC = process.env.TESSERA_EVM_RPC || "";
const KEY = process.env.TESSERA_EVM_KEY || "";
const accounts = KEY ? [KEY.startsWith("0x") ? KEY : `0x${KEY}`] : [];

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "paris",
    },
  },
  networks: {
    // Generic EVM network driven entirely by env (use for any chainId).
    custom: { url: RPC, accounts },
    // Named convenience target for the reference scenario (BNB Chain testnet).
    bnbTestnet: { url: RPC || "https://data-seed-prebsc-1-s1.bnbchain.org:8545", chainId: 97, accounts },
  },
};
