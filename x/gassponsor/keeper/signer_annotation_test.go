package keeper

import (
	"testing"

	msgv1 "cosmossdk.io/api/cosmos/msg/v1"
	gogoproto "github.com/cosmos/gogoproto/proto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// The gov gate in the handler is only half the door. The SDK derives the REQUIRED
// tx signer from the compiled (cosmos.msg.v1.signer) annotation: if it were
// missing, or pointed at any field other than "authority", ANYONE could sign a
// normal tx that sets the authority string to the gov module address and retune
// the gasless mint knobs outside governance.
func TestGassponsorUpdateParams_SignerAnnotationIsAuthority(t *testing.T) {
	d, err := gogoproto.HybridResolver.FindDescriptorByName(
		protoreflect.FullName("cosmos.evm.gassponsor.v1.MsgUpdateParams"))
	if err != nil {
		t.Fatalf("descriptor lookup: %v", err)
	}
	md, ok := d.(protoreflect.MessageDescriptor)
	if !ok {
		t.Fatalf("not a message descriptor: %T", d)
	}
	signers, _ := proto.GetExtension(md.Options(), msgv1.E_Signer).([]string)
	if len(signers) != 1 || signers[0] != "authority" {
		t.Fatalf("signer annotation = %v, want [authority]: the gov gate would be bypassable by a self-signed tx", signers)
	}
}
