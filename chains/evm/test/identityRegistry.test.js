const { expect } = require("chai");
const { ethers } = require("hardhat");

// SHA-256(utf8(value)) — the chain-agnostic DID hash, identical to the C# adapter
// (Tessera.Chains.Abstractions DidHash.Compute) and the Solana program input.
function didHash(value) {
  return ethers.sha256(ethers.toUtf8Bytes(value));
}

const ROOT_A = "0x" + "11".repeat(32);
const ROOT_B = "0x" + "22".repeat(32);
const SIGNING_KEY = "0x" + "ab".repeat(32);

// Build the controller proof the contract requires for registerDid: an EIP-191 personal-sign
// signature by `controllerSigner` over keccak256(abi.encode(didHash, attestationRoot, chainId, registry)).
// signMessage() applies the same "\x19Ethereum Signed Message:\n32" prefix the contract reconstructs.
async function signRegistration(controllerSigner, registryAddress, dh, root) {
  const { chainId } = await ethers.provider.getNetwork();
  const structHash = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "uint256", "address"],
      [dh, root, chainId, registryAddress]
    )
  );
  return controllerSigner.signMessage(ethers.getBytes(structHash));
}

describe("IdentityRegistry", function () {
  let registry, registryAddress, authority, owner, stranger;

  beforeEach(async function () {
    [authority, owner, stranger] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("IdentityRegistry", authority);
    registry = await Factory.deploy(authority.address);
    await registry.waitForDeployment();
    registryAddress = await registry.getAddress();
  });

  // Register `dh`@`root` with `controller` as the proven controller, relayed by `sender`.
  async function register(sender, controller, dh, root) {
    const sig = await signRegistration(controller, registryAddress, dh, root);
    return registry.connect(sender).registerDid(dh, root, controller.address, sig);
  }

  it("rejects a zero authority at construction", async function () {
    const Factory = await ethers.getContractFactory("IdentityRegistry", authority);
    await expect(Factory.deploy(ethers.ZeroAddress)).to.be.revertedWithCustomError(
      registry,
      "ZeroAuthority"
    );
  });

  describe("registerDid", function () {
    it("creates an anchor owned by the proven controller, epoch 0", async function () {
      const dh = didHash("did:tessera:alice");
      await expect(register(owner, owner, dh, ROOT_A))
        .to.emit(registry, "DidRegistered")
        .withArgs(dh, owner.address, ROOT_A);

      const a = await registry.getAnchor(dh);
      expect(a.exists).to.equal(true);
      expect(a.owner).to.equal(owner.address);
      expect(a.attestationRoot).to.equal(ROOT_A);
      expect(a.revocationEpoch).to.equal(0n);
      expect(a.updatedAt).to.be.greaterThan(0n);
    });

    it("lets any relayer submit a valid controller signature (controller need not be the sender)", async function () {
      const dh = didHash("did:tessera:relayed");
      // stranger relays/pays gas; owner is the proven controller and becomes the anchor owner.
      await expect(register(stranger, owner, dh, ROOT_A))
        .to.emit(registry, "DidRegistered")
        .withArgs(dh, owner.address, ROOT_A);
      expect((await registry.getAnchor(dh)).owner).to.equal(owner.address);
    });

    it("rejects a forged controller (signature does not match the claimed controller)", async function () {
      const dh = didHash("did:tessera:victim");
      // Attacker squats the public didHash: signs with their own key but claims `owner` as controller.
      const forgedSig = await signRegistration(stranger, registryAddress, dh, ROOT_A);
      await expect(
        registry.connect(stranger).registerDid(dh, ROOT_A, owner.address, forgedSig)
      ).to.be.revertedWithCustomError(registry, "InvalidSignature");
    });

    it("rejects a signature bound to a different root", async function () {
      const dh = didHash("did:tessera:alice");
      const sigForA = await signRegistration(owner, registryAddress, dh, ROOT_A);
      await expect(
        registry.connect(owner).registerDid(dh, ROOT_B, owner.address, sigForA)
      ).to.be.revertedWithCustomError(registry, "InvalidSignature");
    });

    it("rejects a zero controller", async function () {
      const dh = didHash("did:tessera:alice");
      const sig = await signRegistration(owner, registryAddress, dh, ROOT_A);
      await expect(
        registry.connect(owner).registerDid(dh, ROOT_A, ethers.ZeroAddress, sig)
      ).to.be.revertedWithCustomError(registry, "ZeroController");
    });

    it("reverts on double registration", async function () {
      const dh = didHash("did:tessera:alice");
      await register(owner, owner, dh, ROOT_A);
      await expect(register(owner, owner, dh, ROOT_B)).to.be.revertedWithCustomError(
        registry,
        "AlreadyRegistered"
      );
    });
  });

  describe("updateRoot", function () {
    it("lets the owner replace the root", async function () {
      const dh = didHash("did:tessera:alice");
      await register(owner, owner, dh, ROOT_A);
      await expect(registry.connect(owner).updateRoot(dh, ROOT_B))
        .to.emit(registry, "RootUpdated")
        .withArgs(dh, ROOT_B);
      const a = await registry.getAnchor(dh);
      expect(a.attestationRoot).to.equal(ROOT_B);
    });

    it("rejects a non-owner", async function () {
      const dh = didHash("did:tessera:alice");
      await register(owner, owner, dh, ROOT_A);
      await expect(
        registry.connect(stranger).updateRoot(dh, ROOT_B)
      ).to.be.revertedWithCustomError(registry, "NotOwner");
    });

    it("rejects an unknown DID", async function () {
      await expect(
        registry.connect(owner).updateRoot(didHash("did:tessera:ghost"), ROOT_B)
      ).to.be.revertedWithCustomError(registry, "NotRegistered");
    });
  });

  describe("bumpRevocation", function () {
    it("increments the epoch monotonically, owner-only", async function () {
      const dh = didHash("did:tessera:alice");
      await register(owner, owner, dh, ROOT_A);

      await expect(registry.connect(owner).bumpRevocation(dh, 3))
        .to.emit(registry, "RevocationBumped")
        .withArgs(dh, 1n, 3);
      await registry.connect(owner).bumpRevocation(dh, 0);
      expect((await registry.getAnchor(dh)).revocationEpoch).to.equal(2n);

      await expect(
        registry.connect(stranger).bumpRevocation(dh, 0)
      ).to.be.revertedWithCustomError(registry, "NotOwner");
    });
  });

  describe("issuer registry", function () {
    it("registers and deactivates issuers, authority-only", async function () {
      const ih = didHash("did:tessera:issuer");
      await expect(registry.connect(authority).registerIssuer(ih, SIGNING_KEY, "https://schemas.tessera/kyc/v1"))
        .to.emit(registry, "IssuerRegistered")
        .withArgs(ih, SIGNING_KEY, true, "https://schemas.tessera/kyc/v1");

      let rec = await registry.getIssuer(ih);
      expect(rec.exists).to.equal(true);
      expect(rec.active).to.equal(true);
      expect(rec.signingKey).to.equal(SIGNING_KEY);

      await registry.connect(authority).deactivateIssuer(ih);
      rec = await registry.getIssuer(ih);
      expect(rec.active).to.equal(false);
    });

    it("rejects a non-authority registrant", async function () {
      const ih = didHash("did:tessera:issuer");
      await expect(
        registry.connect(stranger).registerIssuer(ih, SIGNING_KEY, "x")
      ).to.be.revertedWithCustomError(registry, "NotAuthority");
    });

    it("rejects an over-long schema URI", async function () {
      const ih = didHash("did:tessera:issuer");
      const tooLong = "u".repeat(201);
      await expect(
        registry.connect(authority).registerIssuer(ih, SIGNING_KEY, tooLong)
      ).to.be.revertedWithCustomError(registry, "SchemaUriTooLong");
    });
  });

  it("returns a zeroed anchor for an unknown DID", async function () {
    const a = await registry.getAnchor(didHash("did:tessera:nobody"));
    expect(a.exists).to.equal(false);
    expect(a.owner).to.equal(ethers.ZeroAddress);
    expect(a.revocationEpoch).to.equal(0n);
  });
});
