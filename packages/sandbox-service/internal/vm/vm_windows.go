//go:build windows

package vm

import (
	"context"
	"fmt"
	"time"
)

type WindowsSandbox struct {
	id string
}

type WindowsFactory struct{}

func (f *WindowsFactory) Create(ctx context.Context) (OSProcessSandbox, error) {
	id := fmt.Sprintf("sb-win-%d", time.Now().UnixNano())
	return &WindowsSandbox{id: id}, nil
}

func (s *WindowsSandbox) ID() string {
	return s.id
}

// Execute FAILS CLOSED.
//
// The previous implementation ran the untrusted payload as an ordinary process
// (python / cmd.exe) with NO OS-level confinement whatsoever — no Job Object, no
// filesystem or network restriction. That hands out a false sense of containment,
// the same problem the Linux backends refuse to ship. Until Windows isolation is
// implemented we refuse to execute.
//
// Real implementation outline:
//   - create the process suspended (CREATE_SUSPENDED);
//   - assign it to a Job Object with UI, filesystem, network, and resource
//     restrictions (JOB_OBJECT_LIMIT_*), plus a kill-on-close limit so the whole
//     tree dies with the job (the Windows analogue of the Unix process-group kill);
//   - resume the primary thread.
func (s *WindowsSandbox) Execute(ctx context.Context, req ExecRequest) (*ExecResult, error) {
	return nil, fmt.Errorf(
		"windows sandbox backend is not implemented: refusing to execute untrusted code without isolation " +
			"(no Job Object confinement yet); use the macOS backend for now")
}

func (s *WindowsSandbox) Destroy(ctx context.Context) error {
	return nil
}

func NewOSFactory() SandboxFactory {
	return &WindowsFactory{}
}
