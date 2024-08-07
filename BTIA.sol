// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract BTIA is ERC20, Ownable {
    mapping(address => bool) public whiteList;

    bytes32 public DOMAIN_SEPARATOR;

    bytes32 private constant BITA_BRIDGE =
        keccak256(
            abi.encodePacked(
                "Permit(address user,string protocol,string tick,uint256 amountIn,uint256 amountOut,uint256 order,uint256 nonce,uint256 deadline)"
            )
        );

    address public signer;

    mapping(address => uint) public nonces;

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyWhiteList() {
        require(whiteList[msg.sender], "USDA: not in whiteList");
        _;
    }

    event SetWhiteList(address account, bool state);

    event Bridge(
        address caller,
        string protocol,
        string tick,
        uint256 amountIn,
        uint256 amountOut,
        uint256 order
    );

    constructor(address _signer) ERC20("BTIA", "BTIA") {
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
                keccak256(bytes("BTIA")),
                keccak256(bytes("1")),
                chainId,
                address(this)
            )
        );
    }

    function setSigner(address _signer) external onlyOwner {
        signer = _signer;
    }

    function setWhiteList(address account, bool state) external onlyOwner {
        whiteList[account] = state;
        emit SetWhiteList(account, state);
    }

    function mint(address to, uint256 amount) external onlyWhiteList {
        _mint(to, amount);
    }

    /**
     * @dev Destroys `amount` tokens from the caller.
     *
     * See {ERC20-_burn}.
     */
    function burn(uint256 amount) public {
        _burn(_msgSender(), amount);
    }

    /**
     * @dev Destroys `amount` tokens from `account`, deducting from the caller's
     * allowance.
     *
     * See {ERC20-_burn} and {ERC20-allowance}.
     *
     * Requirements:
     *
     * - the caller must have allowance for ``accounts``'s tokens of at least
     * `amount`.
     */
    function burnFrom(address account, uint256 amount) public {
        _spendAllowance(account, _msgSender(), amount);
        _burn(account, amount);
    }

    function withdrawErc20(
        address token,
        address to,
        uint256 amount
    ) public onlyWhiteList {
        uint256 tokenBalance = IERC20(token).balanceOf(address(this));
        require(tokenBalance >= amount, "ERROR:INSUFFICIENT");
        IERC20(token).transfer(to, amount);
    }

    function bridge(bytes calldata data) external {
        (
            address user,
            string memory protocol,
            string memory tick,
            uint256 amountIn,
            uint256 amountOut,
            uint256 order,
            uint256 nonce,
            uint256 deadline,
            bytes memory signature
        ) = abi.decode(
                data,
                (
                    address,
                    string,
                    string,
                    uint256,
                    uint256,
                    uint256,
                    uint256,
                    uint256,
                    bytes
                )
            );
        require(user == msg.sender, "BTIA: invalid user");
        require(nonce == nonces[msg.sender], "BTIA: invalid nonce");
        require(block.timestamp <= deadline, "BTIA: time out");
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);
        bytes32 signHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        BITA_BRIDGE,
                        user,
                        protocol,
                        tick,
                        amountIn,
                        amountOut,
                        order,
                        nonce,
                        deadline
                    )
                )
            )
        );
        require(
            signer == ecrecover(signHash, v, r, s),
            "BTIA: INVALID_REQUEST"
        );
        nonces[msg.sender]++;
        _mint(user, amountOut);
        emit Bridge(user, protocol, tick, amountIn, amountOut, order);
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
