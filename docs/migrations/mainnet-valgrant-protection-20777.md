# Mainnet grant shares remain on their assigned validator

Activation is restricted to the fresh, not-yet-launched `limonata_20777-1`
genesis. Historical `limonata_10777-1` replay retains its existing delegation
and clawback behavior. No existing chain is upgraded by this change.

Active mainnet grants bind the grantee to its own validator address. Issuance
without a validator operator (including the existing EVM precompile) derives that
address and reserves the granted-share ledger for the first self-delegation.
Genesis already seeds the same ledger before delivering the gentx files.

Staking hooks reject transactions which reduce the assigned delegation below
the grant's protected shares, including complete removal, undelegation, and
redelegation. Before the first self-delegation, delegation to another validator
is rejected. Shares above the protected amount remain available to their owner.
Transaction cache rollback is required, as for other x/staking hook errors.

The admin/governance-gated clawback uses a private, grantee-scoped context value
only around its own staking call. Wallet messages cannot request this bypass.
Reclaimed principal returns to the Valgrant reserve, after the standard
unbonding period when applicable. Rewards and personal surplus are not reclaimed.
Slashing can reduce the value recovered; this does not restore slashed tokens.

While a clawback is unbonding, staking changes at its validator are paused for
that grantee. This also rejects cancellation of the admin's unbonding entry.
Other validators, liquid transfers of personal funds, and rewards remain outside
the reclaim. At maturity, a still-live staking entry (including an entry on
hold) delays the sweep rather than consuming gas before principal is returned.

There is no protobuf or store-layout migration. Existing `GrantedShares`,
`TrackedShares`, and `ValidatorOp` fields are reused. A deployed mainnet with
already-escaped shares would need a separately reviewed state migration and
coordinated upgrade; this binary must not be used as an ad hoc replay change.
