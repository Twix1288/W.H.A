const fs = require('fs');
const path = require('path');
const https = require('https');

// Merge freshly-fetched popular packages INTO the curated list rather than
// replacing it. npm's search API ranks by a blended score, not pure downloads,
// so a query alone is not a reliable "top packages" source (the previous
// `text=boost-exact:true` query returned only *boost* packages and silently
// broke typosquat detection). We therefore keep a hand-curated baseline of the
// most-typosquatted packages and only ADD popularity-ranked names to it.
async function fetchTop() {
  console.log('Refreshing popular-package list...');
  const outPath = path.join(__dirname, '../src/commands/popular-packages.json');
  const curated = JSON.parse(fs.readFileSync(outPath, 'utf-8'));
  const fetched = [];
  // Broad, common keywords surface widely-used, high-popularity packages.
  const queries = ['react', 'express', 'cli', 'test', 'http', 'lodash', 'webpack', 'types'];
  try {
    for (const q of queries) {
      const data = await new Promise((resolve, reject) => {
        https
          .get(`https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(q)}&size=100&popularity=1.0`, (res) => {
            let body = '';
            res.on('data', (chunk) => (body += chunk));
            res.on('end', () => resolve(JSON.parse(body)));
          })
          .on('error', reject);
      });
      for (const obj of data.objects || []) {
        const score = obj.score && obj.score.detail ? obj.score.detail.popularity : 0;
        if (score >= 0.5) fetched.push(obj.package.name); // only genuinely popular
      }
    }

    const merged = [...new Set([...curated, ...fetched])].sort();
    fs.writeFileSync(outPath, JSON.stringify(merged, null, 2));
    console.log(`Saved ${merged.length} packages (${curated.length} curated + ${merged.length - curated.length} new) to ${outPath}`);
  } catch (e) {
    console.error('Failed to update popular packages (curated list kept):', e);
    process.exit(1);
  }
}

fetchTop();
