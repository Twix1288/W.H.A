import { parse as parseYaml } from "yaml";
import type { ConfigFile, Finding, Rule, Severity } from "../types.js";

interface LineConfigEntry {
	readonly key: string;
	readonly normalizedKey: string;
	readonly value: string;
	readonly line: number;
}

const RELEASE_AGE_MINUTES = 1440;

function isPackageManagerConfig(file: ConfigFile): boolean {
	return file.type === "package-manager-config";
}

function normalizePath(filePath: string): string {
	return filePath.replace(/\\/g, "/").toLowerCase();
}

function isNpmStyleConfig(file: ConfigFile): boolean {
	const normalized = normalizePath(file.path);
	return normalized.endsWith(".npmrc") || normalized.endsWith(".pnpmrc");
}

function isNpmConfig(file: ConfigFile): boolean {
	return normalizePath(file.path).endsWith(".npmrc");
}

function isPnpmLineConfig(file: ConfigFile): boolean {
	const normalized = normalizePath(file.path);
	return normalized.endsWith(".pnpmrc") || normalized.endsWith("/pnpm/rc");
}

function isYarnConfig(file: ConfigFile): boolean {
	const normalized = normalizePath(file.path);
	return normalized.endsWith(".yarnrc.yml") || normalized.endsWith(".yarnrc");
}

function isPnpmWorkspaceConfig(file: ConfigFile): boolean {
	const normalized = normalizePath(file.path);
	return (
		normalized.endsWith("pnpm-workspace.yaml") ||
		normalized.endsWith("pnpm-workspace.yml")
	);
}

function parseLineConfig(content: string): ReadonlyArray<LineConfigEntry> {
	const entries: LineConfigEntry[] = [];

	for (const [index, rawLine] of content.split("\n").entries()) {
		const trimmed = rawLine.trim();
		if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith(";"))
			continue;

		const assignment = trimmed.match(/^([^=\s]+)\s*=\s*(.*)$/);
		if (!assignment) continue;

		const key = assignment[1].trim();
		const value = stripInlineComment(assignment[2].trim());
		entries.push({
			key,
			normalizedKey: normalizeConfigKey(key),
			value,
			line: index + 1,
		});
	}

	return entries;
}

function stripInlineComment(value: string): string {
	const quoted = value.match(/^(['"])(.*)\1$/);
	if (quoted) return quoted[2];

	const commentIndex = value.search(/\s[#;]/);
	return commentIndex === -1 ? value : value.slice(0, commentIndex).trim();
}

function normalizeConfigKey(key: string): string {
	return key.toLowerCase().replace(/^.*:/, "").replace(/[_-]/g, "");
}

function findEntry(
	entries: ReadonlyArray<LineConfigEntry>,
	key: string,
): LineConfigEntry | undefined {
	const normalizedKey = normalizeConfigKey(key);
	return entries.find((entry) => entry.normalizedKey === normalizedKey);
}

function parseBoolean(value: unknown): boolean | undefined {
	if (typeof value === "boolean") return value;
	if (typeof value === "number") {
		if (value === 1) return true;
		if (value === 0) return false;
	}
	if (typeof value !== "string") return undefined;

	switch (
		value
			.trim()
			.replace(/^['"]|['"]$/g, "")
			.toLowerCase()
	) {
		case "true":
		case "1":
		case "yes":
		case "on":
			return true;
		case "false":
		case "0":
		case "no":
		case "off":
			return false;
		default:
			return undefined;
	}
}

function parseNumber(value: unknown): number | undefined {
	if (typeof value === "number" && Number.isFinite(value)) return value;
	if (typeof value !== "string") return undefined;

	const parsed = Number(value.trim().replace(/^['"]|['"]$/g, ""));
	return Number.isFinite(parsed) ? parsed : undefined;
}

function parseDurationToMinutes(value: unknown): number | undefined {
	if (typeof value === "number" && Number.isFinite(value)) {
		return value * 24 * 60;
	}
	if (typeof value !== "string") return undefined;

	const trimmed = value.trim().replace(/^['"]|['"]$/g, "");
	const match = trimmed.match(/^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)?$/i);
	if (!match) return undefined;

	const amount = Number(match[1]);
	if (!Number.isFinite(amount)) return undefined;

	switch ((match[2] ?? "d").toLowerCase()) {
		case "ms":
			return amount / 60000;
		case "s":
			return amount / 60;
		case "m":
			return amount;
		case "h":
			return amount * 60;
		case "d":
			return amount * 24 * 60;
		case "w":
			return amount * 7 * 24 * 60;
		default:
			return undefined;
	}
}

function parseYamlRecord(content: string): Record<string, unknown> | null {
	try {
		const parsed = parseYaml(content);
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
			return null;
		return parsed as Record<string, unknown>;
	} catch {
		return null;
	}
}

function findYamlLine(content: string, key: string): number | undefined {
	const pattern = new RegExp(`^\\s*${escapeRegExp(key)}\\s*:`, "im");
	const match = pattern.exec(content);
	if (!match || match.index == null) return undefined;
	return content.slice(0, match.index).split("\n").length;
}

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function isEnvReference(value: string): boolean {
	const normalized = value.trim().replace(/^['"]|['"]$/g, "");
	return (
		normalized.startsWith("$") ||
		normalized.includes("${") ||
		normalized.includes("%") ||
		normalized.toLowerCase().includes("process.env")
	);
}

function maskCredential(value: string): string {
	const normalized = value.trim().replace(/^['"]|['"]$/g, "");
	if (normalized.length <= 10) return "<redacted>";
	return `${normalized.slice(0, 6)}...${normalized.slice(-4)}`;
}

function makeFinding(options: {
	readonly id: string;
	readonly severity: Severity;
	readonly category: Finding["category"];
	readonly title: string;
	readonly description: string;
	readonly file: string;
	readonly line?: number;
	readonly evidence?: string;
	readonly before?: string;
	readonly after?: string;
}): Finding {
	return {
		id: options.id,
		severity: options.severity,
		category: options.category,
		title: options.title,
		description: options.description,
		file: options.file,
		line: options.line,
		evidence: options.evidence,
		fix:
			options.before && options.after
				? {
						description: "Harden package-manager configuration",
						before: options.before,
						after: options.after,
						auto: false,
					}
				: undefined,
	};
}

function credentialFindings(file: ConfigFile): ReadonlyArray<Finding> {
	const findings: Finding[] = [];

	if (isNpmStyleConfig(file)) {
		for (const entry of parseLineConfig(file.content)) {
			if (
				!/(?:^|:)_?auth(?:token)?$|(?:^|:)_password$|(?:^|:)password$/.test(
					entry.normalizedKey,
				)
			) {
				continue;
			}
			if (!entry.value || isEnvReference(entry.value)) continue;

			findings.push(
				makeFinding({
					id: `package-manager-registry-credential-${entry.line}`,
					severity: "critical",
					category: "secrets",
					title: "Plaintext package registry credential",
					description:
						"A package-manager config stores a registry credential directly on disk. Use an environment variable reference and rotate the exposed token before relying on package-manager hardening.",
					file: file.path,
					line: entry.line,
					evidence: `${entry.key}=${maskCredential(entry.value)}`,
					before: `${entry.key}=<token>`,
					after: `${entry.key}=\${NPM_TOKEN}`,
				}),
			);
		}
	}

	if (isYarnConfig(file)) {
		const record = parseYamlRecord(file.content);
		if (!record) return findings;

		for (const key of ["npmAuthToken", "npmAuthIdent"]) {
			const value = record[key];
			if (typeof value !== "string" || isEnvReference(value)) continue;

			findings.push(
				makeFinding({
					id: `package-manager-registry-credential-${key}`,
					severity: "critical",
					category: "secrets",
					title: "Plaintext package registry credential",
					description:
						"A Yarn config stores a registry credential directly on disk. Use an environment variable reference and rotate the exposed token before relying on package-manager hardening.",
					file: file.path,
					line: findYamlLine(file.content, key),
					evidence: `${key}: ${maskCredential(value)}`,
					before: `${key}: <token>`,
					after: `${key}: \${NPM_TOKEN}`,
				}),
			);
		}
	}

	return findings;
}

function lifecycleScriptFindings(file: ConfigFile): ReadonlyArray<Finding> {
	const findings: Finding[] = [];

	if (isNpmStyleConfig(file)) {
		const entries = parseLineConfig(file.content);
		const ignoreScripts = findEntry(entries, "ignore-scripts");
		const parsedIgnoreScripts = ignoreScripts
			? parseBoolean(ignoreScripts.value)
			: undefined;

		if (parsedIgnoreScripts === false) {
			findings.push(
				makeFinding({
					id: "package-manager-lifecycle-scripts-enabled",
					severity: "high",
					category: "misconfiguration",
					title: "Package lifecycle scripts are explicitly enabled",
					description:
						"`ignore-scripts=false` allows dependency install scripts to execute. For high-risk AI developer workstations and CI runners, disable lifecycle scripts by default and allowlist required builds separately.",
					file: file.path,
					line: ignoreScripts?.line,
					evidence: `${ignoreScripts?.key}=${ignoreScripts?.value}`,
					before: `${ignoreScripts?.key}=false`,
					after: "ignore-scripts=true",
				}),
			);
		} else if (!ignoreScripts) {
			findings.push(
				makeFinding({
					id: "package-manager-lifecycle-scripts-not-disabled",
					severity: "medium",
					category: "misconfiguration",
					title: "Package lifecycle scripts are not disabled",
					description:
						"This package-manager config does not set `ignore-scripts=true`. Dependency install scripts remain a common supply-chain execution path, including for AI-tooling-focused npm campaigns.",
					file: file.path,
					before: "# missing ignore-scripts",
					after: "ignore-scripts=true",
				}),
			);
		}
	}

	if (isYarnConfig(file)) {
		const record = parseYamlRecord(file.content);
		const enableScripts = record
			? parseBoolean(record.enableScripts)
			: undefined;

		if (enableScripts === true) {
			findings.push(
				makeFinding({
					id: "package-manager-yarn-lifecycle-scripts-enabled",
					severity: "high",
					category: "misconfiguration",
					title: "Yarn lifecycle scripts are explicitly enabled",
					description:
						"`enableScripts: true` lets third-party postinstall scripts run. Keep scripts disabled globally and use package-specific approvals only where the build is required.",
					file: file.path,
					line: findYamlLine(file.content, "enableScripts"),
					evidence: "enableScripts: true",
					before: "enableScripts: true",
					after: "enableScripts: false",
				}),
			);
		}
	}

	if (isPnpmWorkspaceConfig(file)) {
		const record = parseYamlRecord(file.content);
		if (!record) return findings;

		if (parseBoolean(record.dangerouslyAllowAllBuilds) === true) {
			findings.push(
				makeFinding({
					id: "package-manager-pnpm-dangerously-allow-all-builds",
					severity: "high",
					category: "misconfiguration",
					title: "pnpm allows all dependency build scripts",
					description:
						"`dangerouslyAllowAllBuilds: true` disables the package-by-package build review boundary. Keep it off for developer hosts and CI runners that handle secrets.",
					file: file.path,
					line: findYamlLine(file.content, "dangerouslyAllowAllBuilds"),
					evidence: "dangerouslyAllowAllBuilds: true",
					before: "dangerouslyAllowAllBuilds: true",
					after: "strictDepBuilds: true",
				}),
			);
		}

		if (parseBoolean(record.strictDepBuilds) === false) {
			findings.push(
				makeFinding({
					id: "package-manager-pnpm-strict-dep-builds-disabled",
					severity: "medium",
					category: "misconfiguration",
					title: "pnpm strict dependency build review is disabled",
					description:
						"`strictDepBuilds: false` allows dependency lifecycle scripts without forcing an explicit review path. Enable strict dependency builds and allow only known required build scripts.",
					file: file.path,
					line: findYamlLine(file.content, "strictDepBuilds"),
					evidence: "strictDepBuilds: false",
					before: "strictDepBuilds: false",
					after: "strictDepBuilds: true",
				}),
			);
		}
	}

	return findings;
}

function releaseAgeFindings(file: ConfigFile): ReadonlyArray<Finding> {
	const findings: Finding[] = [];

	if (isNpmConfig(file)) {
		const entries = parseLineConfig(file.content);
		const releaseAge =
			findEntry(entries, "min-release-age") ??
			findEntry(entries, "minimum-release-age");

		if (releaseAge) {
			findings.push(
				makeFinding({
					id: "package-manager-npm-release-age-gate-unsupported",
					severity: "medium",
					category: "misconfiguration",
					title: "npm release-age gate key is unsupported",
					description:
						"The npm CLI does not recognize a native dynamic release-age gate. This key can create false confidence; enforce package cooldowns through pnpm `minimumReleaseAge`, Yarn `npmMinimalAgeGate`, or a package-manager policy wrapper.",
					file: file.path,
					line: releaseAge.line,
					evidence: `${releaseAge.key}=${releaseAge.value}`,
					before: `${releaseAge.key}=${releaseAge.value}`,
					after: "# use pnpm minimumReleaseAge or Yarn npmMinimalAgeGate",
				}),
			);
		}
	}

	if (isPnpmLineConfig(file)) {
		const entries = parseLineConfig(file.content);
		const releaseAge = findEntry(entries, "minimum-release-age");
		const releaseAgeValue = releaseAge
			? parseNumber(releaseAge.value)
			: undefined;

		if (!releaseAge) {
			findings.push(
				makeFinding({
					id: "package-manager-pnpm-release-age-gate-missing",
					severity: "info",
					category: "misconfiguration",
					title: "pnpm release-age gate is not configured",
					description:
						"pnpm can block package versions that are too new through `minimumReleaseAge` / `minimum-release-age`. Configure a cooldown to reduce exposure to fast-moving supply-chain campaigns.",
					file: file.path,
					before: "# missing minimum-release-age",
					after: "minimum-release-age=1440",
				}),
			);
		} else if (
			releaseAgeValue !== undefined &&
			releaseAgeValue < RELEASE_AGE_MINUTES
		) {
			findings.push(
				makeFinding({
					id: "package-manager-pnpm-release-age-gate-too-low",
					severity: "medium",
					category: "misconfiguration",
					title: "pnpm release-age gate is below one day",
					description:
						"`minimum-release-age` is below one day. Use a longer cooldown for workstations and CI runners that handle tokens or publish packages.",
					file: file.path,
					line: releaseAge.line,
					evidence: `${releaseAge.key}=${releaseAge.value}`,
					before: `${releaseAge.key}=${releaseAge.value}`,
					after: `${releaseAge.key}=1440`,
				}),
			);
		}
	}

	if (isYarnConfig(file)) {
		const record = parseYamlRecord(file.content);
		const ageGate = record?.npmMinimalAgeGate;
		const ageGateValue = parseDurationToMinutes(ageGate);

		if (ageGate === undefined) {
			findings.push(
				makeFinding({
					id: "package-manager-yarn-release-age-gate-missing",
					severity: "info",
					category: "misconfiguration",
					title: "Yarn npm release-age gate is not configured",
					description:
						"Yarn can block package versions that are too new through `npmMinimalAgeGate`. Configure a cooldown to reduce exposure to newly published malicious packages.",
					file: file.path,
					before: "# missing npmMinimalAgeGate",
					after: 'npmMinimalAgeGate: "1d"',
				}),
			);
		} else if (
			ageGateValue !== undefined &&
			ageGateValue < RELEASE_AGE_MINUTES
		) {
			findings.push(
				makeFinding({
					id: "package-manager-yarn-release-age-gate-too-low",
					severity: "medium",
					category: "misconfiguration",
					title: "Yarn npm release-age gate is below one day",
					description:
						"The configured Yarn age gate is below one day. Use a longer cooldown for workstations and CI runners that handle tokens or publish packages.",
					file: file.path,
					line: findYamlLine(file.content, "npmMinimalAgeGate"),
					evidence: `npmMinimalAgeGate: ${String(ageGate)}`,
					before: `npmMinimalAgeGate: ${String(ageGate)}`,
					after: 'npmMinimalAgeGate: "1d"',
				}),
			);
		}
	}

	if (isPnpmWorkspaceConfig(file)) {
		const record = parseYamlRecord(file.content);
		const releaseAge = record?.minimumReleaseAge;
		const releaseAgeValue = parseNumber(releaseAge);

		if (releaseAge === undefined) {
			findings.push(
				makeFinding({
					id: "package-manager-pnpm-release-age-gate-missing",
					severity: "info",
					category: "misconfiguration",
					title: "pnpm release-age gate is not configured",
					description:
						"pnpm can block package versions that are too new through `minimumReleaseAge`. Configure a cooldown to reduce exposure to fast-moving supply-chain campaigns.",
					file: file.path,
					before: "# missing minimumReleaseAge",
					after: "minimumReleaseAge: 1440",
				}),
			);
		} else if (
			releaseAgeValue !== undefined &&
			releaseAgeValue < RELEASE_AGE_MINUTES
		) {
			findings.push(
				makeFinding({
					id: "package-manager-pnpm-release-age-gate-too-low",
					severity: "medium",
					category: "misconfiguration",
					title: "pnpm release-age gate is below one day",
					description:
						"`minimumReleaseAge` is below one day. Use a longer cooldown for workstations and CI runners that handle tokens or publish packages.",
					file: file.path,
					line: findYamlLine(file.content, "minimumReleaseAge"),
					evidence: `minimumReleaseAge: ${String(releaseAge)}`,
					before: `minimumReleaseAge: ${String(releaseAge)}`,
					after: "minimumReleaseAge: 1440",
				}),
			);
		}
	}

	return findings;
}

export const packageManagerRules: ReadonlyArray<Rule> = [
	{
		id: "package-manager-registry-credentials",
		name: "Package Manager Registry Credentials",
		description:
			"Checks package-manager configs for plaintext registry credentials",
		severity: "critical",
		category: "secrets",
		check(file: ConfigFile): ReadonlyArray<Finding> {
			if (!isPackageManagerConfig(file)) return [];
			return credentialFindings(file);
		},
	},
	{
		id: "package-manager-lifecycle-scripts",
		name: "Package Manager Lifecycle Scripts",
		description:
			"Checks package-manager configs for risky dependency lifecycle script settings",
		severity: "high",
		category: "misconfiguration",
		check(file: ConfigFile): ReadonlyArray<Finding> {
			if (!isPackageManagerConfig(file)) return [];
			return lifecycleScriptFindings(file);
		},
	},
	{
		id: "package-manager-release-age-gates",
		name: "Package Manager Release Age Gates",
		description:
			"Checks package-manager configs for missing or weak package release-age cooldowns",
		severity: "medium",
		category: "misconfiguration",
		check(file: ConfigFile): ReadonlyArray<Finding> {
			if (!isPackageManagerConfig(file)) return [];
			return releaseAgeFindings(file);
		},
	},
];
