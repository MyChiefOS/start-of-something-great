#!/usr/bin/env node
// Builds the JEVs gateway (GATEWAY.md) into one file a Supabase Edge Function can run: gateway/handler.js and
// everything it needs (the site's own handlers, the database layer, JEVs, the postgres driver), bundled by esbuild.
// The only file the code reads at run time, JEVs's word lists, is embedded. The result is committed, and a test
// rebuilds it and fails if it differs, so what runs in Supabase is always exactly what this repository says.
'use strict';

const fs = require('fs');
const path = require('path');
const esbuild = require('esbuild');

const ROOT = path.join(__dirname, '..');
const OUT = path.join(ROOT, 'supabase', 'functions', 'jevs-gateway', 'gateway.js');
const LISTS = path.join(ROOT, 'db', 'jevs-lists');
const READ = "fs.readFileSync(path.join(__dirname, 'jevs-lists', name), 'utf8')";

const embedLists = {
  name: 'embed-jevs-lists',
  setup(build) {
    build.onLoad({ filter: /[\\/]db[\\/]jevs\.js$/ }, async (args) => {
      let src = await fs.promises.readFile(args.path, 'utf8');
      if (!src.includes(READ)) throw new Error('db/jevs.js no longer reads its lists the expected way; update build-gateway.js');
      const lists = Object.fromEntries(fs.readdirSync(LISTS).sort().map((f) => [f, fs.readFileSync(path.join(LISTS, f), 'utf8')]));
      src = src.replace(READ, '__DOG_LISTS[name]') + '\nvar __DOG_LISTS = ' + JSON.stringify(lists) + ';\n';
      return { contents: src, loader: 'js' };
    });
  }
};

async function build({ write = true } = {}) {
  const r = await esbuild.build({
    entryPoints: [path.join(ROOT, 'gateway', 'handler.js')],
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'es2022',
    write: false,
    legalComments: 'none',
    charset: 'utf8',
    logLevel: 'silent',
    plugins: [embedLists],
    banner: { js: '// Built by scripts/build-gateway.js from this repository. Do not edit by hand.\nimport { createRequire as __dogRequire } from "node:module";\nconst require = __dogRequire(import.meta.url);' }
  });
  const text = r.outputFiles[0].text;
  if (write) {
    fs.mkdirSync(path.dirname(OUT), { recursive: true });
    fs.writeFileSync(OUT, text);
  }
  return text;
}

if (require.main === module) build().then((t) => console.log('built', path.relative(ROOT, OUT), t.length, 'bytes')).catch((e) => { console.error(e.message); process.exit(1); });

module.exports = { build, OUT };
