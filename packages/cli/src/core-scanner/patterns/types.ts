import { z } from "zod";
import type { Severity } from "../types.js";

// Shared, tunable pattern rule packs consumed by scan / check / guard. A pack is
// a category of regex detections; a rule is one pattern with severity + the
// guardrail profiles it belongs to. This is the externalized, user-tunable layer
// (YAML files) that unifies detection across all three commands.

export type PatternCategory =
	| "command"
	| "injection"
	| "secret"
	| "sensitive-path";

export type Profile = "permissive" | "default" | "strict";

export const PROFILES: ReadonlyArray<Profile> = [
	"permissive",
	"default",
	"strict",
];

const SeverityEnum = z.enum(["critical", "high", "medium", "low", "info"]);
const CategoryEnum = z.enum([
	"command",
	"injection",
	"secret",
	"sensitive-path",
]);
const ProfileEnum = z.enum(["permissive", "default", "strict"]);

export const PatternRuleSchema = z.object({
	id: z.string().min(1),
	pattern: z.string().min(1),
	flags: z.string().optional(),
	title: z.string().min(1),
	severity: SeverityEnum,
	confidence: z.number().min(0).max(1).optional(),
	tags: z.array(z.string()).optional(),
	// Which guardrail profiles include this rule. Omitted = all profiles.
	profiles: z.array(ProfileEnum).optional(),
});
export type PatternRuleDef = z.infer<typeof PatternRuleSchema>;

export const PackSchema = z.object({
	version: z.number().optional(),
	category: CategoryEnum,
	rules: z.array(PatternRuleSchema),
});
export type PackDef = z.infer<typeof PackSchema>;

// A user override file: adds rules (each MUST carry its own `category`) and/or
// suppresses built-in rule ids.
export const OverrideSchema = z.object({
	version: z.number().optional(),
	suppress: z.array(z.string()).optional(),
	rules: z
		.array(PatternRuleSchema.extend({ category: CategoryEnum }))
		.optional(),
});
export type OverrideDef = z.infer<typeof OverrideSchema>;

export interface CompiledRule {
	readonly id: string;
	readonly re: RegExp;
	readonly title: string;
	readonly severity: Severity;
	readonly category: PatternCategory;
	readonly confidence: number;
	readonly tags: ReadonlyArray<string>;
	readonly profiles: ReadonlyArray<Profile>;
}
