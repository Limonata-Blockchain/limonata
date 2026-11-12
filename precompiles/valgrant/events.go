package valgrant

import (
	"bytes"
	"math/big"
	"reflect"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"

	cmn "github.com/cosmos/evm/precompiles/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	// EventTypeGrantIssued is the event type emitted on a successful issueGrant.
	EventTypeGrantIssued = "GrantIssued"
	// EventTypeGrantClawedBack is the event type emitted on a successful clawback.
	EventTypeGrantClawedBack = "GrantClawedBack"
	// EventTypePoolBurned is the event type emitted on a successful burnPool.
	EventTypePoolBurned = "PoolBurned"
)

// makeGranteeTopics builds the (signature, indexed grantee) topics list.
func (p Precompile) makeGranteeTopics(event abi.Event, grantee common.Address) ([]common.Hash, error) {
	topics := make([]common.Hash, 2)
	topics[0] = event.ID
	t, err := cmn.MakeTopic(grantee)
	if err != nil {
		return nil, err
	}
	topics[1] = t
	return topics, nil
}

// EmitGrantIssuedEvent emits GrantIssued(grantee, lockedAmount, gasAllowance).
func (p Precompile) EmitGrantIssuedEvent(
	ctx sdk.Context,
	stateDB vm.StateDB,
	grantee common.Address,
	lockedAmount, gasAllowance *big.Int,
) error {
	event := p.Events[EventTypeGrantIssued]
	topics, err := p.makeGranteeTopics(event, grantee)
	if err != nil {
		return err
	}

	var b bytes.Buffer
	b.Write(cmn.PackNum(reflect.ValueOf(lockedAmount)))
	b.Write(cmn.PackNum(reflect.ValueOf(gasAllowance)))

	stateDB.AddLog(&ethtypes.Log{
		Address:     p.Address(),
		Topics:      topics,
		Data:        b.Bytes(),
		BlockNumber: uint64(ctx.BlockHeight()), //nolint:gosec // G115 // won't exceed uint64
	})

	return nil
}

// EmitPoolBurnedEvent emits PoolBurned(admin, amount) when pool LIMO is destroyed.
func (p Precompile) EmitPoolBurnedEvent(
	ctx sdk.Context,
	stateDB vm.StateDB,
	admin common.Address,
	amount *big.Int,
) error {
	event := p.Events[EventTypePoolBurned]
	topics, err := p.makeGranteeTopics(event, admin)
	if err != nil {
		return err
	}

	var b bytes.Buffer
	b.Write(cmn.PackNum(reflect.ValueOf(amount)))

	stateDB.AddLog(&ethtypes.Log{
		Address:     p.Address(),
		Topics:      topics,
		Data:        b.Bytes(),
		BlockNumber: uint64(ctx.BlockHeight()), //nolint:gosec // G115 // won't exceed uint64
	})

	return nil
}

// EmitGrantClawedBackEvent emits GrantClawedBack(grantee, undelegated, sweptNow, pending).
func (p Precompile) EmitGrantClawedBackEvent(
	ctx sdk.Context,
	stateDB vm.StateDB,
	grantee common.Address,
	undelegated, sweptNow, pending *big.Int,
) error {
	event := p.Events[EventTypeGrantClawedBack]
	topics, err := p.makeGranteeTopics(event, grantee)
	if err != nil {
		return err
	}

	var b bytes.Buffer
	b.Write(cmn.PackNum(reflect.ValueOf(undelegated)))
	b.Write(cmn.PackNum(reflect.ValueOf(sweptNow)))
	b.Write(cmn.PackNum(reflect.ValueOf(pending)))

	stateDB.AddLog(&ethtypes.Log{
		Address:     p.Address(),
		Topics:      topics,
		Data:        b.Bytes(),
		BlockNumber: uint64(ctx.BlockHeight()), //nolint:gosec // G115 // won't exceed uint64
	})

	return nil
}
