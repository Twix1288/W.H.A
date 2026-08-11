import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

export interface DiscoveredAgent {
	id: string;
	name: string;
	path: string;
}

interface AgentPathDefinition {
	id: string;
	name: string;
	paths: {
		win32: string[];
		darwin: string[];
		linux: string[];
	};
}

const GLOBAL_AGENTS: AgentPathDefinition[] = [
	{
		id: "windsurf",
		name: "Windsurf",
		paths: {
			win32: ["%USERPROFILE%\\.codeium\\windsurf"],
			darwin: ["~/.codeium/windsurf"],
			linux: ["~/.codeium/windsurf"],
		},
	},
	{
		id: "cursor",
		name: "Cursor",
		paths: {
			win32: ["%USERPROFILE%\\.cursor"],
			darwin: ["~/.cursor"],
			linux: ["~/.cursor"],
		},
	},
	{
		id: "vscode",
		name: "VS Code",
		paths: {
			win32: ["%USERPROFILE%\\.vscode"],
			darwin: ["~/.vscode"],
			linux: ["~/.vscode"],
		},
	},
	{
		id: "claude-desktop",
		name: "Claude Desktop",
		paths: {
			win32: ["%APPDATA%\\Claude"],
			darwin: ["~/Library/Application Support/Claude"],
			linux: ["~/.config/Claude"], // Assuming standard XDG
		},
	},
	{
		id: "claude-code",
		name: "Claude Code",
		paths: {
			win32: ["%USERPROFILE%\\.claude"],
			darwin: ["~/.claude"],
			linux: ["~/.claude"],
		},
	},
	{
		id: "gemini-cli",
		name: "Gemini CLI",
		paths: {
			win32: ["%USERPROFILE%\\.gemini"],
			darwin: ["~/.gemini"],
			linux: ["~/.gemini"],
		},
	},
	{
		id: "openclaw",
		name: "OpenClaw",
		paths: {
			win32: ["%USERPROFILE%\\.openclaw"],
			darwin: ["~/.openclaw"],
			linux: ["~/.openclaw"],
		},
	},
	{
		id: "antigravity",
		name: "Antigravity",
		paths: {
			win32: ["%USERPROFILE%\\.gemini\\antigravity-ide"],
			darwin: ["~/.gemini/antigravity-ide"],
			linux: ["~/.gemini/antigravity-ide"],
		},
	},
	{
		id: "codex",
		name: "Codex CLI",
		paths: {
			win32: ["%USERPROFILE%\\.codex"],
			darwin: ["~/.codex"],
			linux: ["~/.codex"],
		},
	},
	{
		id: "continue",
		name: "Continue",
		paths: {
			win32: ["%USERPROFILE%\\.continue"],
			darwin: ["~/.continue"],
			linux: ["~/.continue"],
		},
	},
	{
		id: "zed",
		name: "Zed",
		paths: {
			win32: ["%APPDATA%\\Zed"],
			darwin: ["~/.config/zed", "~/Library/Application Support/Zed"],
			linux: ["~/.config/zed"],
		},
	},
	{
		id: "cline",
		name: "Cline (Claude Dev)",
		paths: {
			// The Cline VS Code extension stores its MCP config + rules under the
			// editor's globalStorage. Cover the common VS Code install locations.
			win32: ["%APPDATA%\\Code\\User\\globalStorage\\saoudrizwan.claude-dev"],
			darwin: [
				"~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev",
			],
			linux: ["~/.config/Code/User/globalStorage/saoudrizwan.claude-dev"],
		},
	},
];

function resolvePath(p: string): string {
	let resolved = p;
	if (resolved.startsWith("~/")) {
		resolved = path.join(os.homedir(), resolved.slice(2));
	}

	// Resolve Windows env vars
	resolved = resolved.replace(/%([^%]+)%/g, (_, n) => process.env[n] || "");

	return path.resolve(resolved);
}

export function discoverGlobalAgents(): DiscoveredAgent[] {
	const discovered: DiscoveredAgent[] = [];
	const platform = process.platform;
	let osKey: "win32" | "darwin" | "linux" = "linux";
	if (platform === "win32") osKey = "win32";
	else if (platform === "darwin") osKey = "darwin";

	for (const agent of GLOBAL_AGENTS) {
		const pathsToCheck = agent.paths[osKey];
		for (const p of pathsToCheck) {
			const resolved = resolvePath(p);
			if (fs.existsSync(resolved)) {
				discovered.push({
					id: agent.id,
					name: agent.name,
					path: resolved,
				});
			}
		}
	}

	return discovered;
}
