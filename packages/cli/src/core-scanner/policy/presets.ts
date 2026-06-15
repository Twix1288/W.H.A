import type { OrgPolicy, PolicyPack } from "./types.js";

export interface PolicyPackSummary {
	readonly id: PolicyPack;
	readonly label: string;
	readonly description: string;
}

export interface GeneratePolicyPackOptions {
	readonly name?: string;
	readonly owners?: ReadonlyArray<string>;
}

const REQUIRED_DESTRUCTIVE_DENY_LIST = ["Bash(rm", "Bash(curl", "Bash(wget"];

const RISKY_MCP_SERVERS = ["shell*", "terminal*"];

const RUNTIME_HOOK = {
	event: "PreToolUse" as const,
	pattern: "wh-agent",
	description: "W.H.Agent runtime monitor must be installed",
};

const POST_TOOL_HOOK = {
	event: "PostToolUse" as const,
	pattern: "wh-agent",
	description: "W.H.Agent post-tool evidence hook must be installed",
};

const PACK_SUMMARIES: ReadonlyArray<PolicyPackSummary> = [
	{
		id: "oss",
		label: "OSS",
		description:
			"Baseline policy for public repositories with permissive contribution paths.",
	},
	{
		id: "team",
		label: "Team",
		description:
			"Default team policy for shared private repositories and active development.",
	},
	{
		id: "enterprise",
		label: "Enterprise",
		description:
			"Stricter organization policy for managed production engineering groups.",
	},
	{
		id: "regulated",
		label: "Regulated",
		description:
			"High-assurance policy for compliance, audit, and sensitive-data environments.",
	},
	{
		id: "high-risk-hooks-mcp",
		label: "High-risk hooks/MCP",
		description:
			"Focused policy for repositories with privileged hooks or MCP integrations.",
	},
	{
		id: "ci-enforcement",
		label: "CI enforcement",
		description:
			"Branch-protection policy tuned for GitHub Actions enforcement gates.",
	},
];

export function listPolicyPacks(): ReadonlyArray<PolicyPackSummary> {
	return PACK_SUMMARIES;
}

export function generatePolicyPack(
	pack: PolicyPack,
	options: GeneratePolicyPackOptions = {},
): OrgPolicy {
	const policy = buildPolicyPack(pack);

	return {
		...policy,
		name: options.name ?? policy.name,
		owners: [...(options.owners ?? policy.owners ?? [])],
	};
}

function buildPolicyPack(pack: PolicyPack): OrgPolicy {
	switch (pack) {
		case "oss":
			return {
				...basePolicy(pack, "W.H.Agent OSS Policy"),
				description:
					"Public-repository baseline for obvious destructive tools and risky shell MCPs.",
				min_score: 70,
				max_severity: "high",
			};
		case "team":
			return {
				...basePolicy(pack, "W.H.Agent Team Policy"),
				description:
					"Shared team baseline with runtime monitoring and risky MCP restrictions.",
				min_score: 75,
				max_severity: "high",
				required_hooks: [RUNTIME_HOOK],
			};
		case "enterprise":
			return {
				...basePolicy(pack, "W.H.Agent Enterprise Policy"),
				description:
					"Managed organization baseline with runtime hooks and strict score gates.",
				min_score: 85,
				max_severity: "high",
				required_hooks: [RUNTIME_HOOK],
				banned_tools: ["Bash(*)"],
			};
		case "regulated":
			return {
				...basePolicy(pack, "W.H.Agent Regulated Policy"),
				description:
					"Compliance baseline for sensitive repositories and regulated environments.",
				min_score: 90,
				max_severity: "medium",
				required_hooks: [RUNTIME_HOOK, POST_TOOL_HOOK],
				banned_mcp_servers: [...RISKY_MCP_SERVERS, "filesystem*", "browser*"],
				banned_tools: ["Bash(*)", "WebFetch(*)"],
			};
		case "high-risk-hooks-mcp":
			return {
				...basePolicy(pack, "W.H.Agent High-risk Hooks/MCP Policy"),
				description:
					"Focused gate for repositories shipping hook code, MCP configs, or plugin manifests.",
				min_score: 80,
				max_severity: "high",
				required_hooks: [RUNTIME_HOOK, POST_TOOL_HOOK],
				banned_mcp_servers: [...RISKY_MCP_SERVERS, "filesystem*"],
				banned_tools: ["Bash(*)"],
			};
		case "ci-enforcement":
			return {
				...basePolicy(pack, "W.H.Agent CI Enforcement Policy"),
				description:
					"Branch-protection baseline for collecting policy status in CI.",
				min_score: 80,
				max_severity: "high",
				required_hooks: [RUNTIME_HOOK],
				banned_tools: ["Bash(*)"],
			};
	}
}

function basePolicy(policyPack: PolicyPack, name: string): OrgPolicy {
	return {
		version: 1,
		name,
		policy_pack: policyPack,
		owners: [],
		exceptions: [],
		required_deny_list: [...REQUIRED_DESTRUCTIVE_DENY_LIST],
		banned_mcp_servers: [...RISKY_MCP_SERVERS],
		min_score: 75,
		max_severity: "high",
		required_hooks: [],
		banned_tools: [],
	};
}
