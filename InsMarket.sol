// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

// Uncomment this line to use console.log
// import "hardhat/console.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/math/MathUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@uniswap/v2-periphery/contracts/interfaces/IUniswapV2Router02.sol";

contract InsMarket is
    Initializable,
    AccessControlEnumerableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{
    using SafeERC20Upgradeable for IERC20Upgradeable;

    bytes32 public constant MANAGE_ROLE = keccak256("MANAGE_ROLE");

    bytes32 public DOMAIN_SEPARATOR;

    bytes32 private constant BUY_PERMIT_TYPEHASH =
        keccak256(
            abi.encodePacked(
                "Permit(address user,uint256 price,address receiver,uint256 fee,address feeReceiver,uint256 order,uint256 nonce,uint256 deadline)"
            )
        );

    bytes32 private constant CANCLE_PERMIT_TYPEHASH =
        keccak256(
            abi.encodePacked(
                "Permit(address user,uint256 fee,address receiver,uint256 order,uint256 nonce,uint256 deadline)"
            )
        );

    address public signer;

    mapping(address => uint) public nonces;

    address public platformAddress;

    event Buy(address buyer, address seller, uint256 price, uint256 order);

    event Cancle(address caller, uint256 order);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(MANAGE_ROLE) {}

    function initialize(
        address _signer,
        address _platformAddress
    ) public initializer {
        __AccessControlEnumerable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MANAGE_ROLE, msg.sender);

        platformAddress = _platformAddress;
        signer = _signer;
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("InsMarket")),
                keccak256(bytes("1")),
                chainId,
                address(this)
            )
        );
    }

    function batchGrantRole(
        bytes32 role,
        address[] calldata accounts
    ) public onlyRole(getRoleAdmin(role)) {
        for (uint i = 0; i < accounts.length; i++) {
            _grantRole(role, accounts[i]);
        }
    }

    function batchRevokeRole(
        bytes32 role,
        address[] calldata accounts
    ) public onlyRole(getRoleAdmin(role)) {
        for (uint i = 0; i < accounts.length; i++) {
            _revokeRole(role, accounts[i]);
        }
    }

    function queryRoles(bytes32 role) public view returns (address[] memory) {
        uint roleNum = getRoleMemberCount(role);
        address[] memory accounts = new address[](roleNum);
        for (uint i = 0; i < roleNum; i++) {
            accounts[i] = getRoleMember(role, i);
        }
        return accounts;
    }

    function balance(address token) public view returns (uint256) {
        if (token == address(0)) {
            return address(this).balance;
        }
        return IERC20Upgradeable(token).balanceOf(address(this));
    }

    receive() external payable {}

    function setPlatformAddress(
        address _platformAddress
    ) public onlyRole(MANAGE_ROLE) {
        platformAddress = _platformAddress;
    }

    function buyInscriptions(bytes calldata data) external {
        (
            address user,
            uint256 price,
            address receiver,
            uint256 fee,
            address feeReceiver,
            uint256 order,
            uint256 nonce,
            uint256 deadline,
            bytes memory signature
        ) = abi.decode(
                data,
                (
                    address,
                    uint256,
                    address,
                    uint256,
                    address,
                    uint256,
                    uint256,
                    uint256,
                    bytes
                )
            );

        require(user == msg.sender, "InsMarket: invalid user");
        require(nonce == nonces[msg.sender], "InsMarket: invalid nonce");
        require(block.timestamp <= deadline, "InsMarket: time out");
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);
        bytes32 signHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        BUY_PERMIT_TYPEHASH,
                        user,
                        price,
                        receiver,
                        fee,
                        feeReceiver,
                        order,
                        nonce,
                        deadline
                    )
                )
            )
        );
        require(
            signer == ecrecover(signHash, v, r, s),
            "InsMarket: INVALID_REQUEST"
        );
        nonces[msg.sender]++;
        emit Buy(user, receiver, price, order);
    }

    function cancleOrder(bytes calldata data) external {
        (
            address user,
            uint256 fee,
            address receiver,
            uint256 order,
            uint256 nonce,
            uint256 deadline,
            bytes memory signature
        ) = abi.decode(
                data,
                (address, uint256, address, uint256, uint256, uint256, bytes)
            );

        require(user == msg.sender, "InsMarket: invalid user");
        require(nonce == nonces[msg.sender], "InsMarket: invalid nonce");
        require(block.timestamp <= deadline, "InsMarket: time out");
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);
        bytes32 signHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        CANCLE_PERMIT_TYPEHASH,
                        user,
                        fee,
                        receiver,
                        order,
                        nonce,
                        deadline
                    )
                )
            )
        );
        require(
            signer == ecrecover(signHash, v, r, s),
            "InsMarket: INVALID_REQUEST"
        );
        nonces[msg.sender]++;
        emit Cancle(user, order);
    }

    function splitSignature(
        bytes memory sig
    ) internal pure returns (uint8, bytes32, bytes32) {
        require(sig.length == 65, "Not Invalid Signature Data");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        return (v, r, s);
    }
}
