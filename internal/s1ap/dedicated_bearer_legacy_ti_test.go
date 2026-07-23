package s1ap

import (
	"testing"

	"github.com/vectorcore/mme/internal/uecontext"
)

func TestAllocateDedicatedLegacyTransactionIdentifierReusesTerminalProcedureValue(t *testing.T) {
	ue := uecontext.NewContext(1)
	ue.PendingBearerTransactions["pending"] = &uecontext.DedicatedBearerTransaction{
		Bearers: map[uint8]*uecontext.DedicatedBearerContext{
			7: {AssignedEBI: 7, LegacyTransactionIdentifier: 2},
			8: {AssignedEBI: 8, LegacyTransactionIdentifier: 3},
		},
	}
	if got := allocateDedicatedLegacyTransactionIdentifierLocked(ue); got != 4 {
		t.Fatalf("identifier with pending 2 and 3 = %d, want 4", got)
	}
	delete(ue.PendingBearerTransactions, "pending") // terminal reject/timeout removes the pending procedure
	if got := allocateDedicatedLegacyTransactionIdentifierLocked(ue); got != 2 {
		t.Fatalf("identifier after terminal procedure = %d, want 2", got)
	}
}
