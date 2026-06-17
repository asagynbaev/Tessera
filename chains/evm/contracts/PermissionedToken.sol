// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IAllowlist {
    function isAllowed(address account) external view returns (bool);
}

/// @title PermissionedToken
/// @notice Minimal permissioned BEP-20 / ERC-20 reference token. Every party to a transfer — and
///         every mint recipient — must be allowed by an external Allowlist contract. Tessera drives
///         that allowlist from off-chain identity verification: an address is added once its holder's
///         presentation satisfies the compliance policy, and removed when KYC is revoked. Removing an
///         address blocks all of its further transfers, on-chain, with no token-side identity logic.
///
/// @dev    This is reference (Layer 3) code, not part of the Tessera product. It holds no identity
///         data — only balances and a pointer to the allowlist that gates them.
contract PermissionedToken {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    address public owner;
    IAllowlist public allowlist;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event AllowlistChanged(address indexed allowlist);

    error NotOwner();
    error NotAllowed(address account);
    error InsufficientBalance();
    error InsufficientAllowance();
    error ZeroAddress();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(string memory name_, string memory symbol_, address allowlist_) {
        if (allowlist_ == address(0)) revert ZeroAddress();
        name = name_;
        symbol = symbol_;
        owner = msg.sender;
        allowlist = IAllowlist(allowlist_);
        emit AllowlistChanged(allowlist_);
    }

    /// @notice Mint to an allowed address. Owner-only.
    function mint(address to, uint256 amount) external onlyOwner {
        if (!allowlist.isAllowed(to)) revert NotAllowed(to);
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    /// @notice Atomically raise a spender's allowance, avoiding the approve() front-running race
    ///         (set-to-N-then-set-to-M lets a watching spender drain N before M lands).
    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
        uint256 updated = allowance[msg.sender][spender] + addedValue; // 0.8 checked add
        allowance[msg.sender][spender] = updated;
        emit Approval(msg.sender, spender, updated);
        return true;
    }

    /// @notice Atomically lower a spender's allowance, clamped at zero.
    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {
        uint256 current = allowance[msg.sender][spender];
        uint256 updated = subtractedValue >= current ? 0 : current - subtractedValue;
        allowance[msg.sender][spender] = updated;
        emit Approval(msg.sender, spender, updated);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 current = allowance[from][msg.sender];
        if (current < amount) revert InsufficientAllowance();
        if (current != type(uint256).max) allowance[from][msg.sender] = current - amount;
        _transfer(from, to, amount);
        return true;
    }

    /// @notice Repoint to a new allowlist (e.g. migrating compliance providers). Owner-only.
    function setAllowlist(address allowlist_) external onlyOwner {
        if (allowlist_ == address(0)) revert ZeroAddress();
        allowlist = IAllowlist(allowlist_);
        emit AllowlistChanged(allowlist_);
    }

    function _transfer(address from, address to, uint256 amount) internal {
        if (!allowlist.isAllowed(from)) revert NotAllowed(from);
        if (!allowlist.isAllowed(to)) revert NotAllowed(to);
        if (balanceOf[from] < amount) revert InsufficientBalance();
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}
