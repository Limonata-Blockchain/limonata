# Limonata mainnet genesis policy

The new chain `limonata_20777-1` starts with a 1,000,000,000 LIMO bank mint
ceiling and a minimum validator self-delegation commitment of 100,000 LIMO.
The native denomination uses 18 decimal places. Other chain IDs, including
historical testnet 10777, keep their previous behavior.

The bank mint restriction is installed before keepers receive the bank keeper,
so every module using `MintCoins` receives the restriction. Initial balances
must independently pass the genesis supply check. Automatic gassponsor refill
and ordinary inflation are disabled in the launch profile. The ceiling applies
to outstanding supply: burning may create headroom below it; it is not a
lifetime cumulative-mint counter. IBC vouchers use separate denominations.

The staking keeper creation hook requires `MinSelfDelegation >= 100000 LIMO`.
The SDK requires the initial self-delegation to meet that commitment, prevents
lowering it on edit, and applies its existing self-delegation rules thereafter.
The keeper hook covers native, authz and precompile calls to validator creation.
Genesis validators must be introduced through the verified gentx ceremony;
pre-populated staking validator state is refused by the launch verifier.

This is a genesis-only policy for the new chain, not a state migration of the
retired testnet. Existing encrypted mempool, DKG and grant state formats are
unchanged. Changing these mainnet constants later requires a coordinated
binary upgrade; they are not adjustable through an ordinary parameter vote.
