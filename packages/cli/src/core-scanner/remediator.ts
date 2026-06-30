import * as fs from 'node:fs/promises';
import { Finding } from './rules';

export async function applyRemediations(filePath: string, findings: Finding[]): Promise<number> {
  const source = await fs.readFile(filePath, 'utf-8');
  let newSource = source;
  
  // Sort findings by startIndex descending so we can apply replacements
  // from back to front without messing up earlier byte offsets!
  let fixableFindings = findings
    .filter(f => f.fixable && f.startIndex !== undefined && f.endIndex !== undefined)
    .sort((a, b) => b.startIndex! - a.startIndex!);

  // Deduplicate by startIndex to prevent multiple rules matching the same node
  // from corrupting the file by applying the same patch multiple times.
  fixableFindings = fixableFindings.filter((f, i, arr) =>
    arr.findIndex(x => x.startIndex === f.startIndex) === i
  );

  if (fixableFindings.length === 0) {
    return 0;
  }

  let fixesApplied = 0;

  for (const finding of fixableFindings) {
    const start = finding.startIndex!;
    const end = finding.endIndex!;
    
    let replacement = '';
    
    if (finding.fixStrategy === 'param_rewrite') {
      // Specifically for WHAgent-EXEC-001 we rewrite shell=True -> shell=False
      // tree-sitter captures the `(true)` node which corresponds to 'True' in Python
      replacement = 'False';
    } else if (finding.fixStrategy === 'literal_stub') {
      replacement = '"" /* wh-agent: removed hardcoded credential — set via environment */';
      
      if (filePath.endsWith('.py') || filePath.endsWith('.sh') || filePath.endsWith('.bash')) {
        replacement = '""  # wh-agent: removed hardcoded credential — set via environment';
      }
    } else {
      continue;
    }

    newSource = newSource.substring(0, start) + replacement + newSource.substring(end);
    fixesApplied++;
  }

  if (fixesApplied > 0) {
    await fs.writeFile(filePath, newSource, 'utf-8');
  }

  return fixesApplied;
}
