const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Allowlist", function () {
  let allowlist, owner, agent, user, stranger;

  beforeEach(async function () {
    [owner, agent, user, stranger] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("Allowlist", owner);
    allowlist = await Factory.deploy();
    await allowlist.waitForDeployment();
  });

  it("owner is an agent by default; unknown addresses are not allowed", async function () {
    expect(await allowlist.agents(owner.address)).to.equal(true);
    expect(await allowlist.isAllowed(user.address)).to.equal(false);
  });

  it("agent can add and remove addresses", async function () {
    await expect(allowlist.addToAllowlist(user.address))
      .to.emit(allowlist, "Allowed")
      .withArgs(user.address);
    expect(await allowlist.isAllowed(user.address)).to.equal(true);

    await expect(allowlist.removeFromAllowlist(user.address))
      .to.emit(allowlist, "Disallowed")
      .withArgs(user.address);
    expect(await allowlist.isAllowed(user.address)).to.equal(false);
  });

  it("rejects the zero address", async function () {
    await expect(allowlist.addToAllowlist(ethers.ZeroAddress)).to.be.revertedWithCustomError(
      allowlist,
      "ZeroAddress"
    );
  });

  it("non-agent cannot modify the list", async function () {
    await expect(
      allowlist.connect(stranger).addToAllowlist(user.address)
    ).to.be.revertedWithCustomError(allowlist, "NotAuthorized");
  });

  it("owner can grant an agent who can then modify the list", async function () {
    await expect(allowlist.setAgent(agent.address, true))
      .to.emit(allowlist, "AgentSet")
      .withArgs(agent.address, true);

    await allowlist.connect(agent).addToAllowlist(user.address);
    expect(await allowlist.isAllowed(user.address)).to.equal(true);

    await allowlist.setAgent(agent.address, false);
    await expect(
      allowlist.connect(agent).addToAllowlist(stranger.address)
    ).to.be.revertedWithCustomError(allowlist, "NotAuthorized");
  });

  it("only owner can set agents", async function () {
    await expect(
      allowlist.connect(stranger).setAgent(stranger.address, true)
    ).to.be.revertedWithCustomError(allowlist, "NotAuthorized");
  });

  it("addToAllowlist is idempotent (second add keeps allowed)", async function () {
    await allowlist.addToAllowlist(user.address);
    await allowlist.addToAllowlist(user.address); // no revert, state unchanged
    expect(await allowlist.isAllowed(user.address)).to.equal(true);
  });

  it("removeFromAllowlist is idempotent (remove when never added)", async function () {
    await allowlist.removeFromAllowlist(user.address); // no revert
    expect(await allowlist.isAllowed(user.address)).to.equal(false);
    await allowlist.addToAllowlist(user.address);
    await allowlist.removeFromAllowlist(user.address);
    await allowlist.removeFromAllowlist(user.address); // second remove, still false
    expect(await allowlist.isAllowed(user.address)).to.equal(false);
  });
});
