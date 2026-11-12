package types

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// RequireCompleteParamsJSON enforces the SDK's documented MsgUpdateParams contract
// ("all parameters must be supplied") instead of merely stating it in a comment.
//
// WHY: MsgUpdateParams carries the params as an opaque JSON blob that is decoded
// into a ZERO Params struct. A proposal that omits a key therefore does not "leave
// that setting alone" - it RESETS it. For x/vpcap an omitted "enabled" silently
// switches the voting-power cap OFF; for x/gassponsor an omitted cap decodes as ""
// which the module reads as UNLIMITED MINTING. x/encmempool hit this exact class of
// bug and had to bolt a one-way ratchet onto its handler after the fact.
//
// A ratchet is the wrong fix here (governance must be able to move these values in
// BOTH directions - raising a cap as the validator set grows is legitimate). So the
// rule is not "you may only tighten", it is "you must say what you mean": every
// field of Params must appear explicitly in the payload. Governance keeps full
// authority; it just cannot exercise it by accident, and a voter reading the
// proposal sees every value that will be in force.
//
// It is a pure function over the message payload: it reads no state and decides
// nothing about the VALUES, only about which keys are present.
func RequireCompleteParamsJSON(bz []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(bz, &raw); err != nil {
		return fmt.Errorf("invalid params json: %w", err)
	}
	var missing []string
	t := reflect.TypeOf(Params{})
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			continue
		}
		if _, ok := raw[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf(
			"params is missing %d key(s) [%s]: this message REPLACES the whole params struct, so an omitted key is silently RESET to its zero value - supply every field explicitly",
			len(missing), strings.Join(missing, ", "))
	}
	// Reject unknown keys too: a typo'd key ("enable" for "enabled") would otherwise
	// pass the completeness check on the real field's absence... it would not, but a
	// typo ALONGSIDE the real key would silently do nothing. Fail loudly instead.
	known := make(map[string]struct{}, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		if name := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]; name != "" && name != "-" {
			known[name] = struct{}{}
		}
	}
	var unknown []string
	for k := range raw {
		if _, ok := known[k]; !ok {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("params carries %d unknown key(s) [%s]: refusing a payload this build cannot honour",
			len(unknown), strings.Join(unknown, ", "))
	}
	return nil
}
