const fs = require('fs');
const path = require('path');
const https = require('https');

async function fetchTop() {
  console.log('Fetching top npm packages...');
  let pkgs = [];
  try {
    for (let i = 0; i < 2; i++) {
      const data = await new Promise((resolve, reject) => {
        https.get(`https://registry.npmjs.org/-/v1/search?text=boost-exact:true&size=250&from=${i*250}`, (res) => {
          let body = '';
          res.on('data', chunk => body += chunk);
          res.on('end', () => resolve(JSON.parse(body)));
        }).on('error', reject);
      });
      
      for (const obj of (data.objects || [])) {
        pkgs.push(obj.package.name);
      }
    }
    
    const uniquePkgs = [...new Set(pkgs)];
    const outPath = path.join(__dirname, '../src/commands/popular-packages.json');
    fs.writeFileSync(outPath, JSON.stringify(uniquePkgs, null, 2));
    console.log(`Saved ${uniquePkgs.length} packages to ${outPath}`);
  } catch (e) {
    console.error('Failed to update popular packages:', e);
    process.exit(1);
  }
}

fetchTop();
