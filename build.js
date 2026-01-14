const esbuild = require('esbuild');
const fs = require('fs');
const path = require('path');

const isWatch = process.argv.includes('--watch');

const entries = [
  { in: 'src/background/service-worker.ts', out: 'dist/background/service-worker.js' },
  { in: 'src/content/content-script.ts', out: 'dist/content/content-script.js' },
  { in: 'src/popup/popup.ts', out: 'dist/popup/popup.js' },
  { in: 'src/options/options.ts', out: 'dist/options/options.js' }
];

async function run() {
  // Ensure directories
  const dirs = ['dist/background', 'dist/content', 'dist/popup', 'dist/options', 'dist/styles', 'dist/assets/icons'];
  dirs.forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });

  // Copy static files
  const copyStatics = () => {
    try {
      fs.copyFileSync('manifest.json', 'dist/manifest.json');
      fs.copyFileSync('src/popup/popup.html', 'dist/popup/popup.html');
      fs.copyFileSync('src/options/options.html', 'dist/options/options.html');

      // Copy icons recursively
      const copyDir = (src, dest) => {
        if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
        fs.readdirSync(src).forEach(file => {
          const s = path.join(src, file);
          const d = path.join(dest, file);
          if (fs.lstatSync(s).isDirectory()) copyDir(s, d);
          else fs.copyFileSync(s, d);
        });
      };
      copyDir('src/assets', 'dist/assets');

      console.log('[Build] Statics and assets copied');
    } catch (err) {
      console.warn('[Build] Statics/assets copy failed:', err.message);
    }
  };
  copyStatics();

  const getOptions = (entry) => ({
    entryPoints: [entry.in],
    bundle: true,
    outfile: entry.out,
    format: 'iife',
    target: 'es2020',
    minify: !isWatch,
    sourcemap: isWatch,
  });

  if (isWatch) {
    console.log('[Build] Entering watch mode...');
    for (const entry of entries) {
      const ctx = await esbuild.context(getOptions(entry));
      await ctx.watch();
    }
  } else {
    for (const entry of entries) {
      await esbuild.build(getOptions(entry));
      console.log(`[Build] Done: ${entry.out}`);
    }
    console.log('[Build] Fully complete');
  }
}

run().catch(e => {
  console.error('[Build] Critical error:', e);
  process.exit(1);
});
