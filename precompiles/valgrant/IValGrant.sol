// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.8.17;

/// @dev The ValGrant contract's address.
address constant VALGRANT_PRECOMPILE_ADDRESS = 0x0000000000000000000000000000000000000900;

/// @dev The ValGrant contract's instance.
IValGrant constant VALGRANT_CONTRACT = IValGrant(VALGRANT_PRECOMPILE_ADDRESS);

/// @author Limonata
/// @title ValGrant Precompile Contract
/// @dev Admin-only precompile for the Limonata x/valgrant module. Lets the
/// configured admin wallet (msg.sender must equal x/valgrant Params.admin,
/// derived as the cosmos bech32 of the caller) issue validator locked-grants and
/// claw them back as native EVM transactions, fully non-custodial.
///
/// All amounts are in aLIMO (18-decimal base denom): 1 LIMO = 1e18 aLIMO.
interface IValGrant {
    /// @dev GrantIssued is emitted when a locked grant is issued.
    /// @param grantee The address that received the PermanentLockedAccount grant.
    /// @param lockedAmount The locked principal funded (aLIMO).
    /// @param gasAllowance The liquid gas allowance funded (aLIMO).
    event GrantIssued(
        address indexed grantee,
        uint256 lockedAmount,
        uint256 gasAllowance
    );

    /// @dev GrantClawedBack is emitted when a grant is revoked.
    /// @param grantee The address whose grant was clawed back.
    /// @param undelegated The total bonded principal sent to unbonding.
    /// @param sweptNow The principal swept back to the pool immediately.
    /// @param pending The principal still unbonding (swept later, after unbonding).
    event GrantClawedBack(
        address indexed grantee,
        uint256 undelegated,
        uint256 sweptNow,
        uint256 pending
    );

    /// @dev PoolBurned is emitted when pool LIMO is permanently destroyed.
    /// @param admin The admin that triggered the burn.
    /// @param amount The aLIMO amount destroyed (removed from total supply).
    event PoolBurned(address indexed admin, uint256 amount);

    /// @dev issueGrant creates a PermanentLockedAccount for grantee and funds it
    /// from the valgrant reserve pool: lockedAmount locked principal (stakeable,
    /// never sellable) + gasAllowance liquid (to pay fees). Admin-only.
    /// @param grantee The (fresh) account to receive the locked grant.
    /// @param lockedAmount The locked principal in aLIMO.
    /// @param gasAllowance The liquid gas allowance in aLIMO.
    /// @return success True on success.
    function issueGrant(
        address grantee,
        uint256 lockedAmount,
        uint256 gasAllowance
    ) external returns (bool success);

    /// @dev clawback force-undelegates the grantee's delegations and sweeps the
    /// locked principal back to the reserve pool, leaving earned rewards + gas
    /// with the grantee, and marks the grant revoked. Admin-only.
    /// @param grantee The grantee whose grant to revoke.
    /// @return success True on success.
    function clawback(address grantee) external returns (bool success);

    /// @dev burnPool permanently DESTROYS LIMO from the valgrant reserve pool:
    /// the coins are removed from the module account AND from total supply,
    /// proving reclaimed bootstrap capital never comes back to anyone. Admin-only.
    /// @param amount The aLIMO amount to destroy. 0 burns the ENTIRE current pool
    /// balance.
    /// @return burned The aLIMO amount actually destroyed.
    function burnPool(uint256 amount) external returns (uint256 burned);
}
