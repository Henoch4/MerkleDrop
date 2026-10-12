// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title MerkleDrop — multi-campaign merkle airdrops for any ERC20.
/// Owner creates campaigns (token + root + total), funds them, anyone with a
/// valid proof claims once. Owner can close a campaign and reclaim leftovers.
contract MerkleDrop is ReentrancyGuard, Ownable {
    struct Campaign {
        address token;
        bytes32 root;
        uint256 total;
        uint256 claimed;
        bool closed;
    }

    Campaign[] private _camps;
    mapping(uint256 => mapping(address => bool)) public hasClaimed;

    event CampaignCreated(uint256 indexed id, address indexed token, bytes32 root, uint256 total);
    event Funded(uint256 indexed id, uint256 amount);
    event Claimed(uint256 indexed id, address indexed account, uint256 amount);
    event CampaignClosed(uint256 indexed id, uint256 reclaimed);

    constructor() Ownable(msg.sender) {}

    function createCampaign(address token, bytes32 root, uint256 total) external onlyOwner returns (uint256) {
        require(token != address(0), "Zero token");
        require(total > 0, "Bad total");
        _camps.push(Campaign(token, root, total, 0, false));
        uint256 id = _camps.length - 1;
        emit CampaignCreated(id, token, root, total);
        return id;
    }

    function fund(uint256 id, uint256 amount) external onlyOwner nonReentrant {
        Campaign storage c = _camps[id];
        require(!c.closed, "Closed");
        require(IERC20(c.token).transferFrom(msg.sender, address(this), amount), "Fund failed");
        emit Funded(id, amount);
    }

    function claim(uint256 id, address account, uint256 amount, bytes32[] calldata proof)
        external
        nonReentrant
    {
        Campaign storage c = _camps[id];
        require(!c.closed, "Closed");
        require(!hasClaimed[id][account], "Already claimed");
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(account, amount))));
        require(MerkleProof.verify(proof, c.root, leaf), "Bad proof");
        hasClaimed[id][account] = true;
        c.claimed += amount;
        require(c.claimed <= c.total, "Over total");
        require(IERC20(c.token).transfer(account, amount), "Pay failed");
        emit Claimed(id, account, amount);
    }

    function close(uint256 id) external onlyOwner nonReentrant {
        Campaign storage c = _camps[id];
        require(!c.closed, "Closed");
        c.closed = true;
        uint256 bal = IERC20(c.token).balanceOf(address(this));
        if (bal > 0) require(IERC20(c.token).transfer(msg.sender, bal), "Reclaim failed");
        emit CampaignClosed(id, bal);
    }

    function totalCampaigns() external view returns (uint256) {
        return _camps.length;
    }

    function getCampaign(uint256 id)
        external
        view
        returns (address token, bytes32 root, uint256 total, uint256 claimed, bool closed)
    {
        Campaign storage c = _camps[id];
        return (c.token, c.root, c.total, c.claimed, c.closed);
    }
}
