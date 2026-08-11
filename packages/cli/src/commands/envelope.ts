import { existsSync, readFileSync } from "node:fs";
import * as path from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";

/**
 * A single host subtree opened to the sandboxed process, matching the Go
 * `vm.PathRule` shape (PascalCase keys are what the sandbox binary unmarshals).
 */
export interface PathRule {
	readonly Path: string;
	readonly Write: boolean;
}

/**
 * The enforceable slice of the envelope: which host subtrees the tool may touch
 * and the single local egress proxy it may reach. Everything else stays denied
 * by the sandbox. Telemetry/credential blocks in the YAML are advisory-only today
 * and intentionally not represented here (we don't pretend to enforce them).
 */
export interface SandboxScope {
	readonly allowPaths: ReadonlyArray<PathRule>;
	readonly egressProxy?: string;
	/** Non-fatal notes to surface to the user (e.g. a declared mount that is missing). */
	readonly warnings: ReadonlyArray<string>;
}

// Lenient schema: unknown keys are ignored so the richer shipped envelope.yaml
// (credentials/telemetry blocks) parses without error; we only read what we can
// actually enforce.
const MountSchema = z.object({
	path: z.string(),
	mode: z.enum(["ro", "rw"]).optional(),
});

const EnvelopeSchema = z
	.object({
		storage: z
			.object({ mounts: z.array(MountSchema).optional() })
			.loose()
			.optional(),
		network: z
			.object({ egress_proxy: z.string().optional() })
			.loose()
			.optional(),
	})
	.loose();

const HOST_PORT_RE = /^[A-Za-z0-9.\-:]+:\d{1,5}$/;

/**
 * Parse an envelope file into the enforceable sandbox scope. Missing file →
 * empty scope (the sandbox stays hermetic, preserving today's default). Mount
 * paths are resolved relative to `cwd`; a declared mount that does not exist is
 * skipped with a warning rather than bricking the run (the Go backend fails
 * closed on an unresolvable path, so we never forward one).
 */
export function loadSandboxScope(
	envelopePath: string,
	cwd: string = process.cwd(),
): SandboxScope {
	const resolved = path.isAbsolute(envelopePath)
		? envelopePath
		: path.resolve(cwd, envelopePath);

	if (!existsSync(resolved)) {
		return { allowPaths: [], warnings: [] };
	}

	let doc: unknown;
	try {
		doc = parseYaml(readFileSync(resolved, "utf-8"));
	} catch (err) {
		throw new Error(
			`Failed to parse envelope ${resolved}: ${err instanceof Error ? err.message : String(err)}`,
		);
	}

	const parsed = EnvelopeSchema.safeParse(doc ?? {});
	if (!parsed.success) {
		throw new Error(
			`Invalid envelope ${resolved}: ${parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`,
		);
	}

	const warnings: string[] = [];
	const allowPaths: PathRule[] = [];
	for (const mount of parsed.data.storage?.mounts ?? []) {
		const abs = path.isAbsolute(mount.path)
			? mount.path
			: path.resolve(cwd, mount.path);
		if (!existsSync(abs)) {
			warnings.push(
				`envelope mount "${mount.path}" does not exist (resolved ${abs}) — skipped`,
			);
			continue;
		}
		allowPaths.push({ Path: abs, Write: mount.mode === "rw" });
	}

	let egressProxy: string | undefined;
	const rawProxy = parsed.data.network?.egress_proxy?.trim();
	if (rawProxy) {
		if (!HOST_PORT_RE.test(rawProxy)) {
			throw new Error(
				`Invalid envelope ${resolved}: network.egress_proxy "${rawProxy}" must be host:port (e.g. 127.0.0.1:8888).`,
			);
		}
		egressProxy = rawProxy;
	}

	return { allowPaths, egressProxy, warnings };
}
