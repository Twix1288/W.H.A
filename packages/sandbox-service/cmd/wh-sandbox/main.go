package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"wh-agent/sandbox-service/internal/executor"
	"wh-agent/sandbox-service/internal/vm"
)

func main() {
	var req vm.ExecRequest
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse request: %v\n", err)
		os.Exit(1)
	}

	factory := vm.NewOSFactory()
	engine := executor.NewEngine(1, factory)

	res, err := engine.Execute(context.Background(), req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox execution failed: %v\n", err)
		os.Exit(1)
	}

	if err := json.NewEncoder(os.Stdout).Encode(res); err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode result: %v\n", err)
		os.Exit(1)
	}
}
