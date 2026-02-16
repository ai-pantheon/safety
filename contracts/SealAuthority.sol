// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/**
 * @title SealAuthority
 * @notice One node in the Safety 7-chain seal authority network.
 *
 * Holds a single Shamir share of the production seal secret.
 * Verifies Cloak proofs before releasing partial seals.
 *
 * The seal secret is split 4-of-7 across independent blockchains.
 * This contract is one of those 7 authorities. It verifies that the
 * requesting Cloak ran its full anonymization pipeline before releasing
 * its share contribution.
 *
 * Architecture:
 *   Client Cloak → submits proof → contract verifies → returns partial seal
 *   No user data touches this contract. No identity is stored.
 *   The contract knows nothing about who is requesting — only that
 *   the Cloak pipeline ran correctly.
 */
contract SealAuthority {
    // ── State ──

    /// @notice The encrypted Shamir share (encrypted with the authority admin key)
    bytes public encryptedShare;

    /// @notice The share index in the Shamir scheme (1-7)
    uint8 public shareIndex;

    /// @notice Threshold required for reconstruction
    uint8 public threshold;

    /// @notice Total shares in the scheme
    uint8 public totalShares;

    /// @notice Authorized Cloak signer addresses (can request seals)
    mapping(address => bool) public authorizedSigners;

    /// @notice Admin address (can update signers and share)
    address public admin;

    /// @notice Whether the authority is active
    bool public active;

    /// @notice Nonces to prevent replay attacks
    mapping(bytes32 => bool) public usedNonces;

    // ── Events ──

    event SealRequested(address indexed requester, uint256 timestamp);
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event ShareUpdated(uint8 shareIndex);
    event AuthorityDeactivated();

    // ── Errors ──

    error Unauthorized();
    error InvalidProof();
    error AuthorityInactive();
    error NonceAlreadyUsed();
    error InvalidSignature();

    // ── Modifiers ──

    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }

    modifier onlyActive() {
        if (!active) revert AuthorityInactive();
        _;
    }

    // ── Constructor ──

    constructor(uint8 _shareIndex, uint8 _threshold, uint8 _totalShares) {
        admin = msg.sender;
        shareIndex = _shareIndex;
        threshold = _threshold;
        totalShares = _totalShares;
        active = true;
    }

    // ── Core: Seal Request ──

    /**
     * @notice Request this authority's partial seal.
     * @dev Verifies the Cloak proof before releasing.
     *
     * @param proofHash     SHA-256 hash of the Cloak proof fields
     * @param nonce         Unique nonce to prevent replay
     * @param timestamp     When the proof was generated (must be recent)
     * @param pipelineFlags Bitfield: bit 0 = padding, bit 1 = metadata stripped, bit 2 = shuffled
     * @param signature     ECDSA signature of (proofHash, nonce, timestamp, pipelineFlags)
     *
     * @return The encrypted share bytes (client decrypts off-chain)
     */
    function requestSeal(
        bytes32 proofHash,
        bytes32 nonce,
        uint256 timestamp,
        uint8 pipelineFlags,
        bytes calldata signature
    ) external onlyActive returns (bytes memory) {
        // 1. Check nonce hasn't been used (prevent replay)
        if (usedNonces[nonce]) revert NonceAlreadyUsed();
        usedNonces[nonce] = true;

        // 2. Verify timestamp is recent (within 120 seconds)
        if (block.timestamp > timestamp + 120 || timestamp > block.timestamp + 30) {
            revert InvalidProof();
        }

        // 3. Verify all pipeline flags are set
        //    Bit 0: padding applied
        //    Bit 1: metadata stripped
        //    Bit 2: shuffle applied
        if (pipelineFlags & 0x07 != 0x07) revert InvalidProof();

        // 4. Verify the signature is from an authorized Cloak signer
        bytes32 messageHash = keccak256(
            abi.encodePacked(proofHash, nonce, timestamp, pipelineFlags)
        );
        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
        address signer = _recoverSigner(ethSignedHash, signature);
        if (!authorizedSigners[signer]) revert InvalidSignature();

        // 5. All checks passed — release the encrypted share
        emit SealRequested(msg.sender, timestamp);
        return encryptedShare;
    }

    // ── Admin Functions ──

    /**
     * @notice Store the encrypted share.
     * @dev The share is encrypted off-chain. This contract stores ciphertext only.
     */
    function setShare(bytes calldata _encryptedShare) external onlyAdmin {
        encryptedShare = _encryptedShare;
        emit ShareUpdated(shareIndex);
    }

    /**
     * @notice Add an authorized Cloak signer.
     */
    function addSigner(address signer) external onlyAdmin {
        authorizedSigners[signer] = true;
        emit SignerAdded(signer);
    }

    /**
     * @notice Remove an authorized Cloak signer.
     */
    function removeSigner(address signer) external onlyAdmin {
        authorizedSigners[signer] = false;
        emit SignerRemoved(signer);
    }

    /**
     * @notice Transfer admin rights.
     */
    function transferAdmin(address newAdmin) external onlyAdmin {
        admin = newAdmin;
    }

    /**
     * @notice Deactivate this authority (emergency kill switch).
     */
    function deactivate() external onlyAdmin {
        active = false;
        emit AuthorityDeactivated();
    }

    /**
     * @notice Reactivate this authority.
     */
    function activate() external onlyAdmin {
        active = true;
    }

    // ── Internal ──

    /**
     * @dev Recover ECDSA signer from a signed message hash.
     */
    function _recoverSigner(
        bytes32 ethSignedHash,
        bytes memory signature
    ) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) v += 27;
        require(v == 27 || v == 28, "Invalid signature v value");

        return ecrecover(ethSignedHash, v, r, s);
    }

    // ── View Functions ──

    /**
     * @notice Check if an address is an authorized signer.
     */
    function isSigner(address addr) external view returns (bool) {
        return authorizedSigners[addr];
    }

    /**
     * @notice Get authority info.
     */
    function info() external view returns (
        uint8 _shareIndex,
        uint8 _threshold,
        uint8 _totalShares,
        bool _active,
        bool _hasShare
    ) {
        return (
            shareIndex,
            threshold,
            totalShares,
            active,
            encryptedShare.length > 0
        );
    }
}
