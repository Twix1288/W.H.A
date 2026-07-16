//go:build windows

package vm

import (
	"context"
	"strings"
	"testing"
)

// The Windows backend must FAIL CLOSED. It previously ran the untrusted payload
// as an ordinary process with no Job Object / no confinement at all. Until real
// Windows isolation lands, Execute must refuse rather than run with fake
// containment.
func TestWindowsFailsClosed(t *testing.T) {
	s, err := (&WindowsFactory{}).Create(context.Background())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := s.Execute(context.Background(), ExecRequest{
		Code:     "print('should not run')",
		Language: "python",
	})
	if err == nil {
		t.Fatalf("windows backend executed the payload instead of failing closed (result=%+v)", res)
	}
	if !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// The Windows factory is the only backend on this OS, so NewOSFactory must return
// it (and, per the fail-closed Execute above, that backend refuses to run).
func TestWindowsFactorySelected(t *testing.T) {
	if _, ok := NewOSFactory().(*WindowsFactory); !ok {
		t.Fatalf("NewOSFactory did not return *WindowsFactory on windows")
	}
}
