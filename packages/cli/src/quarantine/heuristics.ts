export interface QuarantineResult {
	shouldQuarantine: boolean;
	reasons: string[];
}

export interface PackageMeta {
	name: string;
	version: string;
	publishedAt: Date;
	weeklyDownloads: number;
	registrySource: "private" | "public";
	maintainerVerified: boolean;
	tarballUrl: string;
	signature: string;
}

export class QuarantineHeuristics {
	private readonly MAX_AGE_DAYS = 14;
	private readonly MIN_WEEKLY_DOWNLOADS = 100;

	async evaluate(meta: PackageMeta): Promise<QuarantineResult> {
		// Private registry packages are always trusted
		if (meta.registrySource === "private") {
			return { shouldQuarantine: false, reasons: [] };
		}

		const reasons: string[] = [];
		const ageInDays = this.getAgeInDays(meta.publishedAt);

		if (ageInDays < this.MAX_AGE_DAYS) {
			reasons.push(
				`Package is only ${ageInDays} days old (minimum: ${this.MAX_AGE_DAYS} days)`,
			);
		}

		if (meta.weeklyDownloads < this.MIN_WEEKLY_DOWNLOADS) {
			reasons.push(
				`Only ${meta.weeklyDownloads} weekly downloads (minimum: ${this.MIN_WEEKLY_DOWNLOADS})`,
			);
		}

		if (!meta.maintainerVerified) {
			reasons.push("Maintainer identity is unverified");
		}

		// Combined risk: young AND low downloads = dependency confusion attack vector
		if (
			ageInDays < this.MAX_AGE_DAYS &&
			meta.weeklyDownloads < this.MIN_WEEKLY_DOWNLOADS
		) {
			reasons.push(
				"HIGH RISK: Age + download count combination matches dependency confusion pattern",
			);
		}

		return { shouldQuarantine: reasons.length > 0, reasons };
	}

	private getAgeInDays(publishedAt: Date): number {
		return Math.floor(
			(Date.now() - publishedAt.getTime()) / (1000 * 60 * 60 * 24),
		);
	}
}
