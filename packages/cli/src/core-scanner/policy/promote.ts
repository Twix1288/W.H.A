import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { POLICY_EXPORT_SCHEMA_VERSION } from "./export.js";
import type { PolicyPack } from "./types.js";
import { OrgPolicySchema, PolicyPackSchema } from "./types.js";

export interface PromotePolicyPackOptions {
	readonly manifestPath: string;
	readonly outputPath: string;
	readonly pack?: PolicyPack;
	readonly dryRun?: boolean;
}

export interface PolicyPackPromotionResult {
	readonly manifestPath: string;
	readonly sourceFile: string;
	readonly outputPath: string;
	readonly pack: PolicyPack;
	readonly policyName: string;
	readonly owners: ReadonlyArray<string>;
	readonly sha256: string;
	readonly verified: true;
	readonly promoted: boolean;
	readonly dryRun: boolean;
	readonly reviewItems: ReadonlyArray<PolicyPackPromotionReviewItem>;
}

export interface PolicyPackPromotionReviewItem {
	readonly id: string;
	readonly status: "verified" | "action_required";
	readonly severity: "info" | "medium";
	readonly title: string;
	readonly detail: string;
	readonly evidencePaths: ReadonlyArray<string>;
	readonly recommendation: string;
}

interface ExportManifestEntry {
	readonly id: PolicyPack;
	readonly file: string;
	readonly sha256: string;
}

interface ExportManifest {
	readonly schema_version: typeof POLICY_EXPORT_SCHEMA_VERSION;
	readonly packs: ReadonlyArray<ExportManifestEntry>;
}

export function promotePolicyPack(
	options: PromotePolicyPackOptions,
): PolicyPackPromotionResult {
	const manifest = readExportManifest(options.manifestPath);
	const entry = selectPolicyPack(manifest.packs, options.pack);
	const sourceFile = isAbsolute(entry.file)
		? entry.file
		: join(dirname(options.manifestPath), entry.file);

	if (!existsSync(sourceFile)) {
		throw new Error(`Policy file not found: ${sourceFile}`);
	}

	const policyJson = readFileSync(sourceFile, "utf-8");
	const actualDigest = digest(policyJson);
	if (actualDigest !== entry.sha256) {
		throw new Error(
			`Policy digest mismatch for ${entry.id}: expected ${entry.sha256}, got ${actualDigest}`,
		);
	}

	const parsed = JSON.parse(policyJson);
	const policy = OrgPolicySchema.parse(parsed);
	if (policy.policy_pack !== entry.id) {
		throw new Error(
			`Policy pack mismatch: manifest entry is ${entry.id}, policy file declares ${policy.policy_pack}`,
		);
	}

	const owners = policy.owners ?? [];
	const dryRun = Boolean(options.dryRun);
	const promoted = !dryRun;

	if (!dryRun) {
		mkdirSync(dirname(options.outputPath), { recursive: true });
		writeFileSync(options.outputPath, policyJson);
	}

	return {
		manifestPath: options.manifestPath,
		sourceFile,
		outputPath: options.outputPath,
		pack: entry.id,
		policyName: policy.name ?? "Organization Policy",
		owners,
		sha256: entry.sha256,
		verified: true,
		promoted,
		dryRun,
		reviewItems: buildPromotionReviewItems({
			manifestPath: options.manifestPath,
			sourceFile,
			outputPath: options.outputPath,
			pack: entry.id,
			owners,
			sha256: entry.sha256,
			dryRun,
			promoted,
		}),
	};
}

function buildPromotionReviewItems(options: {
	readonly manifestPath: string;
	readonly sourceFile: string;
	readonly outputPath: string;
	readonly pack: PolicyPack;
	readonly owners: ReadonlyArray<string>;
	readonly sha256: string;
	readonly dryRun: boolean;
	readonly promoted: boolean;
}): ReadonlyArray<PolicyPackPromotionReviewItem> {
	const policyForSmoke = options.promoted
		? options.outputPath
		: options.sourceFile;

	return [
		{
			id: "manifest-digest-verified",
			status: "verified",
			severity: "info",
			title: "Manifest digest verified",
			detail: `${options.pack} matched ${options.sha256}.`,
			evidencePaths: [options.manifestPath, options.sourceFile],
			recommendation:
				"Attach the manifest and exported policy to the policy promotion review.",
		},
		{
			id: "policy-owner-review",
			status: options.owners.length > 0 ? "verified" : "action_required",
			severity: options.owners.length > 0 ? "info" : "medium",
			title: "Policy owner review",
			detail:
				options.owners.length > 0
					? `Owners: ${options.owners.join(", ")}.`
					: "No policy owners are declared on the exported policy.",
			evidencePaths: [options.sourceFile],
			recommendation:
				options.owners.length > 0
					? "Require one listed owner to approve the protected rollout PR."
					: "Add at least one policy owner before promoting this pack outside a sandbox.",
		},
		{
			id: "protected-rollout-pr",
			status: options.promoted ? "verified" : "action_required",
			severity: options.promoted ? "info" : "medium",
			title: "Protected rollout path",
			detail: options.promoted
				? `Active policy written to ${options.outputPath}.`
				: `Dry run only; ${options.outputPath} was not written.`,
			evidencePaths: [options.manifestPath, options.sourceFile],
			recommendation: options.promoted
				? "Keep subsequent policy changes behind branch protection, CI, and owner approval."
				: `Open a protected PR that promotes ${options.sourceFile} to ${options.outputPath} and requires CI plus owner approval.`,
		},
		{
			id: "runtime-smoke-test",
			status: "action_required",
			severity: "medium",
			title: "Runtime smoke test",
			detail: `Promotion did not run a repository scan with ${policyForSmoke}.`,
			evidencePaths: [policyForSmoke],
			recommendation: `Run wh-agent scan --policy ${policyForSmoke} before enabling this policy as an enforcing CI gate.`,
		},
	];
}

function readExportManifest(manifestPath: string): ExportManifest {
	if (!existsSync(manifestPath)) {
		throw new Error(`Policy export manifest not found: ${manifestPath}`);
	}

	const raw = JSON.parse(readFileSync(manifestPath, "utf-8")) as {
		readonly schema_version?: unknown;
		readonly packs?: unknown;
	};

	if (raw.schema_version !== POLICY_EXPORT_SCHEMA_VERSION) {
		throw new Error(
			`Unsupported policy export manifest schema: ${String(raw.schema_version)}`,
		);
	}

	if (!Array.isArray(raw.packs)) {
		throw new Error("Policy export manifest is missing a packs array");
	}

	return {
		schema_version: POLICY_EXPORT_SCHEMA_VERSION,
		packs: raw.packs.map(readManifestEntry),
	};
}

function readManifestEntry(entry: unknown): ExportManifestEntry {
	if (!entry || typeof entry !== "object") {
		throw new Error("Invalid policy export manifest entry");
	}

	const candidate = entry as {
		readonly id?: unknown;
		readonly file?: unknown;
		readonly sha256?: unknown;
	};
	const packResult = PolicyPackSchema.safeParse(candidate.id);
	if (!packResult.success) {
		throw new Error(
			`Invalid policy pack id in manifest: ${String(candidate.id)}`,
		);
	}
	if (typeof candidate.file !== "string" || candidate.file.length === 0) {
		throw new Error(
			`Invalid policy file for manifest pack: ${packResult.data}`,
		);
	}
	if (
		typeof candidate.sha256 !== "string" ||
		!/^sha256:[a-f0-9]{64}$/.test(candidate.sha256)
	) {
		throw new Error(
			`Invalid policy digest for manifest pack: ${packResult.data}`,
		);
	}

	return {
		id: packResult.data,
		file: candidate.file,
		sha256: candidate.sha256,
	};
}

function selectPolicyPack(
	entries: ReadonlyArray<ExportManifestEntry>,
	requestedPack: PolicyPack | undefined,
): ExportManifestEntry {
	if (requestedPack) {
		const entry = entries.find((item) => item.id === requestedPack);
		if (!entry) {
			throw new Error(
				`Policy pack ${requestedPack} not found in export manifest`,
			);
		}
		return entry;
	}

	if (entries.length === 1) {
		return entries[0]!;
	}

	throw new Error(
		"Export manifest contains multiple policy packs; pass --pack to select one",
	);
}

function digest(value: string): string {
	return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
