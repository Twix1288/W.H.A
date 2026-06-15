import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

export interface ConformanceDiagnostic {
  line: number;
  column?: number;
  severity: 'error' | 'warning' | 'info';
  ruleId: string;
  message: string;
}

export interface ConformanceScore {
  totalScore: number;           // 0-100
  frontmatterScore: number;     // 0-40
  structureScore: number;       // 0-40
  securityScore: number;        // 0-20
  diagnostics: ConformanceDiagnostic[];
  passed: boolean;
}

export class ConformanceScorer {
  async score(artifact: Buffer): Promise<ConformanceScore> {
    const diagnostics: ConformanceDiagnostic[] = [];
    let frontmatterScore = 40;
    let structureScore = 40;
    let securityScore = 20;

    let content = "";
    try {
      content = await this.extractSkillMd(artifact);
    } catch (e: any) {
      return {
        totalScore: 0, frontmatterScore: 0, structureScore: 0, securityScore: 0,
        diagnostics: [{ line: 1, severity: 'error', ruleId: 'extraction_failed', message: `Failed to extract SKILL.md: ${e.message}` }],
        passed: false
      };
    }

    const { frontmatter, body } = this.parseSkillMd(content);

    // Frontmatter Evaluation (Max 40)
    if (!frontmatter) {
      frontmatterScore -= 40;
      diagnostics.push({ line: 1, severity: 'error', ruleId: 'missing_frontmatter', message: 'SKILL.md is missing YAML frontmatter' });
    } else {
      if (!frontmatter.includes('name:')) {
        frontmatterScore -= 10;
        diagnostics.push({ line: 1, severity: 'warning', ruleId: 'frontmatter_missing_name', message: 'Frontmatter missing name field' });
      }
      if (!frontmatter.includes('description:')) {
        frontmatterScore -= 10;
        diagnostics.push({ line: 1, severity: 'warning', ruleId: 'frontmatter_missing_description', message: 'Frontmatter missing description field' });
      }
    }

    // Structure Evaluation (Max 40)
    if (!body.toLowerCase().includes('example') && !body.toLowerCase().includes('usage')) {
      structureScore -= 20;
      diagnostics.push({ line: 1, severity: 'warning', ruleId: 'structure_missing_examples', message: 'Package is missing usage examples in its markdown' });
    }

    // Security Evaluation (Max 20)
    if (!body.toLowerCase().includes('security') && !body.toLowerCase().includes('permission')) {
      securityScore -= 10;
      diagnostics.push({ line: 1, severity: 'warning', ruleId: 'security_missing_section', message: 'No explicit security or permission constraints mentioned' });
    }

    const totalScore = Math.max(0, frontmatterScore) +
                       Math.max(0, structureScore) +
                       Math.max(0, securityScore);

    return {
      totalScore,
      frontmatterScore: Math.max(0, frontmatterScore),
      structureScore: Math.max(0, structureScore),
      securityScore: Math.max(0, securityScore),
      diagnostics,
      passed: totalScore >= 70,
    };
  }

  private async extractSkillMd(artifact: Buffer): Promise<string> {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wh-agent-'));
      const tarPath = path.join(tmpDir, 'package.tar.gz');
      fs.writeFileSync(tarPath, artifact);
      
      try {
        execSync(`tar -xzf ${tarPath} -C ${tmpDir}`);
        const skillPath = path.join(tmpDir, 'SKILL.md');
        if (!fs.existsSync(skillPath)) {
            throw new Error("SKILL.md not found in package root");
        }
        return fs.readFileSync(skillPath, 'utf-8');
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
  }

  private parseSkillMd(content: string): { frontmatter: string | null, body: string } {
      const match = content.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
      if (match) {
          return { frontmatter: match[1], body: match[2] };
      }
      return { frontmatter: null, body: content };
  }
}
