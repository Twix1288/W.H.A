//go:build linux
package vm

import (
    "context"
    "strings"
    "testing"
)

// The default Linux backend must FAIL CLOSED: it must never run untrusted code
// with no isolation. Until real Landlock enforcement lands, Execute must return
// an error instead of executing the payload.
func TestLandlockFailsClosed(t *testing.T) {
    s, err := (&LandlockFactory{}).Create(context.Background())
    if err != nil {
        t.Fatalf("create: %v", err)
    }
    res, err := s.Execute(context.Background(), ExecRequest{
        Code:     "open('/etc/shadow').read()",
        Language: "python",
    })
    if err == nil {
        t.Fatalf("landlock backend executed the payload instead of failing closed (result=%+v)", res)
    }
    if !strings.Contains(err.Error(), "not implemented") {
        t.Fatalf("unexpected error message: %v", err)
    }
}

// The default factory (no WH_SANDBOX_BACKEND set) must select the fail-closed
// Landlock backend rather than silently running unsandboxed.
func TestDefaultBackendIsFailClosed(t *testing.T) {
    t.Setenv("WH_SANDBOX_BACKEND", "")
    if f := NewOSFactory(); func() bool { _, ok := f.(*LandlockFactory); return !ok }() {
        t.Fatalf("default backend is %T, want *LandlockFactory (fail-closed)", f)
    }
}
