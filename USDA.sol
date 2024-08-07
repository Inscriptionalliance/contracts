// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract USDA is ERC20, Ownable {
    mapping(address => bool) public whiteList;

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyWhiteList() {
        require(whiteList[msg.sender], "USDA: not in whiteList");
        _;
    }

    event SetWhiteList(address account, bool state);

    event Swap(
        address caller,
        address tokenIn,
        address tokenOut,
        uint256 tokenInAmount,
        uint256 tokenOutAmount
    );

    constructor() ERC20("USDA", "USDA") {}

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

    function swap(
        address tokenIn,
        address tokenOut,
        uint tokenInAmount
    ) external {
        require(
            tokenIn == address(this) || tokenOut == address(this),
            "USDTA: token error"
        );
        if (tokenIn == address(this)) {
            _spendAllowance(msg.sender, address(this), tokenInAmount);
            _burn(msg.sender, tokenInAmount);
            IERC20(tokenOut).transfer(msg.sender, tokenInAmount);
        } else {
            IERC20(tokenIn).transferFrom(
                msg.sender,
                address(this),
                tokenInAmount
            );
            _mint(msg.sender, tokenInAmount);
        }
        emit Swap(msg.sender, tokenIn, tokenOut, tokenInAmount, tokenInAmount);
    }
}
