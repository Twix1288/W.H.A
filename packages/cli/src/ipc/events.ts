/**
 * W.H.Agent IPC Telemetry Schema
 * Frozen. Versioned ("v": 1). This is the explicit contract between the Linux VM
 * (shield-agent) and the native CLI (Node.js).
 */

export type EventVersion = 1;

export interface BaseEvent {
	v: EventVersion;
	ts: number; // Unix timestamp
	type: string; // Event type discriminator
}

export interface NetworkBlockEvent extends BaseEvent {
	type: "network_block";
	dst_ip: string;
	dst_port: number;
	process: string;
	pid: number;
}

export interface SyscallViolationEvent extends BaseEvent {
	type: "syscall_violation";
	syscall: string;
	pid: number;
	process: string;
}

export interface PromptInjectionEvent extends BaseEvent {
	type: "prompt_injection";
	turn: number;
	confidence: number;
}

export interface StatusRequestEvent extends BaseEvent {
	type: "status_request";
	// Internal control message for querying probe counts
}

export interface StatusResponseEvent extends BaseEvent {
	type: "status_response";
	probes_attached: number;
	health: "healthy" | "degraded";
}

export type ShieldEvent =
	| NetworkBlockEvent
	| SyscallViolationEvent
	| PromptInjectionEvent
	| StatusRequestEvent
	| StatusResponseEvent;
