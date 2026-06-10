const { expect } = require("chai");
const { ethers } = require("hardhat");

// Reference (Layer 3) test: a permissioned token gated by the Allowlist that Tessera drives.
// Demonstrates the headline invariant — revoking an address blocks its transfers on-chain.
describe("PermissionedToken", function () {
  let allowlist, token, owner, alice, bob, carol;

  beforeEach(async function () {
    [owner, alice, bob, carol] = await ethers.getSigners();

    const Allowlist = await ethers.getContractFactory("Allowlist", owner);
    allowlist = await Allowlist.deploy();
    await allowlist.waitForDeployment();

    const Token = await ethers.getContractFactory("PermissionedToken", owner);
    token = await Token.deploy("Compliant USD", "cUSD", await allowlist.getAddress());
    await token.waitForDeployment();

    // Tessera admits alice and bob (their presentations satisfied the policy).
    await allowlist.addToAllowlist(alice.address);
    await allowlist.addToAllowlist(bob.address);
  });

  it("mints only to allowed addresses", async function () {
    await expect(token.mint(carol.address, 100n)).to.be.revertedWithCustomError(token, "NotAllowed");
    await token.mint(alice.address, 1000n);
    expect(await token.balanceOf(alice.address)).to.equal(1000n);
  });

  it("transfers between allowed addresses", async function () {
    await token.mint(alice.address, 1000n);
    await expect(token.connect(alice).transfer(bob.address, 400n))
      .to.emit(token, "Transfer")
      .withArgs(alice.address, bob.address, 400n);
    expect(await token.balanceOf(bob.address)).to.equal(400n);
  });

  it("blocks transfer to a non-allowed recipient", async function () {
    await token.mint(alice.address, 1000n);
    await expect(token.connect(alice).transfer(carol.address, 100n))
      .to.be.revertedWithCustomError(token, "NotAllowed")
      .withArgs(carol.address);
  });

  it("revoking KYC (removeFromAllowlist) blocks the revoked holder's transfers", async function () {
    await token.mint(alice.address, 1000n);
    await token.connect(alice).transfer(bob.address, 200n); // works while both allowed

    // Tessera revokes bob (KYC expired / sanctioned).
    await allowlist.removeFromAllowlist(bob.address);

    // bob can no longer send...
    await expect(token.connect(bob).transfer(alice.address, 50n))
      .to.be.revertedWithCustomError(token, "NotAllowed")
      .withArgs(bob.address);
    // ...and can no longer receive.
    await expect(token.connect(alice).transfer(bob.address, 50n))
      .to.be.revertedWithCustomError(token, "NotAllowed")
      .withArgs(bob.address);
  });

  it("transferFrom respects the allowlist for both parties", async function () {
    await token.mint(alice.address, 1000n);
    await token.connect(alice).approve(bob.address, 500n);

    await token.connect(bob).transferFrom(alice.address, bob.address, 300n);
    expect(await token.balanceOf(bob.address)).to.equal(300n);

    await allowlist.removeFromAllowlist(alice.address);
    await expect(
      token.connect(bob).transferFrom(alice.address, bob.address, 100n)
    ).to.be.revertedWithCustomError(token, "NotAllowed").withArgs(alice.address);
  });
});
