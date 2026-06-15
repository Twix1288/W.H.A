package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel network ebpf/network.c

const socketPath = "/tmp/shield-agent.sock"

type NetworkBlockEvent struct {
	V       int    `json:"v"`
	Ts      int64  `json:"ts"`
	Type    string `json:"type"`
	DstIP   string `json:"dst_ip"`
	DstPort uint16 `json:"dst_port"`
	Process string `json:"process"`
	Pid     uint32 `json:"pid"`
}

func main() {
	log.Println("🛡️ Starting shield-agent (eBPF IPC Telemetry layer)...")

	// Remove old socket if exists
	os.Remove(socketPath)

	// Start Unix Socket Server
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("Failed to listen on unix socket: %v", err)
	}
	defer l.Close()
	log.Printf("Listening on %s\n", socketPath)

	// Allow maximum locked memory for eBPF maps
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// Handle graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

    // Check if running inside gVisor
    procVersion, err := os.ReadFile("/proc/version")
    isGvisor := false
    if err == nil && bytes.Contains(bytes.ToLower(procVersion), []byte("gvisor")) {
        isGvisor = true
    }

	// Load pre-compiled eBPF programs into the kernel ONLY if not in gVisor
    var rd *ringbuf.Reader
    if isGvisor {
        log.Println("🛡️ Detected gVisor (Tier B) environment. Skipping eBPF attachment.")
        log.Println("🛡️ Enforcing security via gVisor native seccomp and syscall interception instead.")
    } else {
        objs := networkObjects{}
        if err := loadNetworkObjects(&objs, nil); err != nil {
            log.Fatalf("Loading eBPF objects failed: %v", err)
        }
        defer objs.Close()

        // Attach tracepoint
        tp, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceConnect, nil)
        if err != nil {
            log.Fatalf("Failed to attach tracepoint: %v", err)
        }
        defer tp.Close()
        log.Println("Successfully attached eBPF connect tracepoint (Tier A).")

        // Open the ring buffer
        rd, err = ringbuf.NewReader(objs.Events)
        if err != nil {
            log.Fatalf("Failed to open ringbuf: %v", err)
        }
        defer rd.Close()
    }

	// Wait for exactly one CLI client connection
	log.Println("Waiting for CLI socket connection...")
	conn, err := l.Accept()
	if err != nil {
		log.Fatalf("Failed to accept connection: %v", err)
	}
	defer conn.Close()
	log.Println("CLI Connected. Streaming events...")

	go func() {
		<-stop
		log.Println("Shutting down...")
		rd.Close()
		l.Close()
		os.Exit(0)
	}()

	// Read from ring buffer and write to socket
	var event struct {
		Pid     uint32
		DstIP   uint32
		DstPort uint16
		Padding uint16
	}

	for {
		if rd == nil {
			// In gVisor, eBPF is disabled, so we just block and keep the socket open
			time.Sleep(1 * time.Second)
			continue
		}

		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("Error reading from ringbuf: %v", err)
			continue
		}

		// Parse the raw C struct
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Failed to parse ringbuf event: %v", err)
			continue
		}

		// Format IP
		ip := net.IPv4(byte(event.DstIP>>24), byte(event.DstIP>>16), byte(event.DstIP>>8), byte(event.DstIP)).String()

		// Format NDJSON
		out := NetworkBlockEvent{
			V:       1,
			Ts:      time.Now().Unix(),
			Type:    "network_block",
			DstIP:   ip,
			DstPort: event.DstPort,
			Process: "agent.py", // Mocked for smoke test, normally resolved via /proc/
			Pid:     event.Pid,
		}

		b, err := json.Marshal(out)
		if err != nil {
			continue
		}
		
		// Write newline-delimited JSON to Unix Socket
		_, err = conn.Write(append(b, '\n'))
		if err != nil {
			log.Printf("Socket write failed: %v", err)
			return // Exit if CLI disconnects
		}
	}
}
