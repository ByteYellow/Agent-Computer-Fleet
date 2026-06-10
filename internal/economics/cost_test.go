package economics

import "testing"

func TestAdmitUsesActiveCPUAndMemorySafety(t *testing.T) {
	ok := Admit(AdmissionInput{
		PhysicalCPU:       4,
		OvercommitRatio:   2,
		ActiveCPURequest:  6,
		IdleCPURequest:    10,
		IdleDiscount:      0.1,
		MemoryAllocatedMB: 512,
		MemoryRequestMB:   512,
		MemoryTotalMB:     2048,
		MemorySafetyRatio: 0.9,
	})
	if !ok {
		t.Fatalf("expected idle-discounted CPU request to be admitted")
	}

	ok = Admit(AdmissionInput{
		PhysicalCPU:       4,
		OvercommitRatio:   2,
		ActiveCPURequest:  9,
		IdleCPURequest:    0,
		MemoryAllocatedMB: 0,
		MemoryRequestMB:   256,
		MemoryTotalMB:     2048,
	})
	if ok {
		t.Fatalf("expected active CPU over capacity to be rejected")
	}

	ok = Admit(AdmissionInput{
		PhysicalCPU:       8,
		OvercommitRatio:   2,
		ActiveCPURequest:  1,
		MemoryAllocatedMB: 1900,
		MemoryRequestMB:   200,
		MemoryTotalMB:     2048,
		MemorySafetyRatio: 0.9,
	})
	if ok {
		t.Fatalf("expected unsafe memory allocation to be rejected")
	}
}
