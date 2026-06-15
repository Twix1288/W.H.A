/**
 * MiniClaw Entry Point
 *
 * Provides the public API for starting and embedding MiniClaw.
 * Re-exports all types and key functions for consumers.
 *
 * Usage as a standalone server:
 *   import { startMiniClaw } from '@wh-agent/miniclaw';
 *   const { stop } = await startMiniClaw();
 *
 * Usage as an embedded module:
 *   import { createMiniClawSession, routePrompt } from '@wh-agent/miniclaw';
 *   const session = await createMiniClawSession();
 *   const response = await routePrompt(request, session);
 */

// ─── Type Re-exports ──────────────────────────────────────

export type {
	AllowedTool,
	MiniClawConfig,
	MiniClawSession,
	NetworkPolicy,
	PromptRequest,
	PromptResponse,
	SandboxConfig,
	SecurityEvent,
	SecurityEventType,
	ServerConfig,
	TokenUsage,
	ToolCallRecord,
	ToolCallRequest,
	ToolRiskLevel,
	ToolValidationResult,
	ToolWhitelist,
} from "./types.js";

export {
	DEFAULT_SANDBOX_CONFIG,
	DEFAULT_SERVER_CONFIG,
} from "./types.js";

// ─── Module Re-exports ────────────────────────────────────

export {
	filterResponse,
	routePrompt,
	sanitizePrompt,
} from "./router.js";
export {
	checkFileSize,
	createSandbox,
	createSecurityEvent,
	destroySandbox,
	validateExtension,
	validatePath,
} from "./sandbox.js";
export {
	createMiniClawServer,
	startServer,
} from "./server.js";
export {
	createCustomWhitelist,
	createGuardedWhitelist,
	createSafeWhitelist,
	executeToolCall,
	getToolsByRiskLevel,
	scopeToolCall,
	TOOL_REGISTRY,
	validateToolCall,
} from "./tools.js";

// ─── Convenience Functions ────────────────────────────────

import type { createServer } from "node:http";
import { createSandbox } from "./sandbox.js";
import { startServer } from "./server.js";
import { createSafeWhitelist } from "./tools.js";
import type { MiniClawConfig, MiniClawSession } from "./types.js";
import { DEFAULT_SANDBOX_CONFIG, DEFAULT_SERVER_CONFIG } from "./types.js";

/**
 * Starts a MiniClaw server with the provided (or default) configuration.
 *
 * This is the simplest way to run MiniClaw — a single function call
 * that sets up the sandbox, tool whitelist, and HTTP server.
 *
 * @param config - Optional partial configuration. Unspecified fields use secure defaults.
 * @returns A handle with the server instance and a stop function
 */
export function startMiniClaw(config?: Partial<MiniClawConfig>): {
	readonly server: ReturnType<typeof createServer>;
	readonly stop: () => void;
} {
	const fullConfig: MiniClawConfig = {
		sandbox: config?.sandbox ?? DEFAULT_SANDBOX_CONFIG,
		server: config?.server ?? DEFAULT_SERVER_CONFIG,
		tools: config?.tools ?? createSafeWhitelist(),
	};

	return startServer(fullConfig);
}

/**
 * Creates a MiniClaw session programmatically, without starting a server.
 *
 * Use this when embedding MiniClaw into an existing application that
 * already has its own HTTP server. The session can be used directly
 * with routePrompt() for prompt processing.
 *
 * @param config - Optional partial sandbox configuration
 * @returns A new MiniClaw session with a sandbox directory
 */
export async function createMiniClawSession(
	config?: Partial<{
		readonly sandbox: Partial<import("./types.js").SandboxConfig>;
		readonly tools: import("./types.js").ToolWhitelist;
	}>,
): Promise<MiniClawSession> {
	const sandboxConfig = {
		...DEFAULT_SANDBOX_CONFIG,
		...config?.sandbox,
	};

	const tools = config?.tools ?? createSafeWhitelist();

	return createSandbox(sandboxConfig, tools.tools, sandboxConfig.maxDuration);
}
