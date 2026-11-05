// Write the site's design.css from Aaron's design stylesheet (static/css/styles.css), as written, with three changes the
// production site needs: the fonts are the site's own files (no Google Fonts: style-src and font-src are 'self'); the
// theme follows the visitor's system setting (the prototype's toggle was "prototype behaviour only"); and the inputs'
// borders use --rule-strong (CODING_AGENT_SPEC.md 5.1). Then every inline style from the ported pages, as a class.
'use strict';
const fs = require('fs');
const [designCss, siteStyles, stylesJson, out] = process.argv.slice(2);
let css = fs.readFileSync(designCss, 'utf8');
const fonts = (fs.readFileSync(siteStyles, 'utf8').match(/@font-face \{[\s\S]*?\}/g) || []).join('\n');
const dark = css.match(/\.d1\[data-theme=dark\]\{([^}]*)\}/)[1];
const light = css.match(/\.d1\[data-theme=light\]\{([^}]*)\}/)[1];
css = css.replace(/\.d1\[data-theme=dark\]\{[^}]*\}\n?/, '').replace(/\.d1\[data-theme=light\]\{[^}]*\}\n?/, '');
css = css.replace(/^\/\*[^*]*\*\/\n/, '');
// Inputs, selects and textareas: --rule-strong (3:1), the handoff's token for interactive borders.
css = css.replace(/(\.d1 input\{[^}]*?)border:1px solid var\(--rule\)/, '$1border:1px solid var(--rule-strong)')
  .replace(/(\.d1 textarea\{[^}]*?)border:1px solid var\(--rule\)/, '$1border:1px solid var(--rule-strong)')
  .replace(/(\.d1 select\{[^}]*?)border:1px solid var\(--rule\)/, '$1border:1px solid var(--rule-strong)');
// The one rule that reads inline styles: under 820 px, any grid written inline becomes one column.
const styles = JSON.parse(fs.readFileSync(stylesJson, 'utf8'));
const gridded = Object.keys(styles).filter((c) => /grid-template-columns/.test(styles[c]));
css = css.replace('.d1 [style*="grid-template-columns"]{grid-template-columns:1fr!important}', gridded.map((c) => '.d1 .' + c + '.' + c).join(',') + '{grid-template-columns:1fr!important}');
const imp = (decl) => decl.split(/;(?![^(]*\))/).map((d) => d.trim()).filter(Boolean).map((d) => (/!important$/.test(d) ? d : d + '!important')).join(';');
const inline = Object.keys(styles).sort().map((c) => '.d1 .' + c + '{' + imp(styles[c]) + '}').join('\n');
const head = `/* Day One Great: Aaron's design (the handoff of Nov 5, 2026, static/css/styles.css), as written. Changes for production
   only: the site's own font files, the theme from the visitor's system setting, --rule-strong on form fields (spec 5.1),
   and the design's inline styles as classes (x...) with the same values, since the security policy allows no inline style. */
[hidden]{display:none!important}
/* The search filters are buttons (so they can be pressed), drawn as the design's chips. */
.d1 .chips button{min-height:0;padding:4px 14px;border:1px solid var(--rule);border-radius:999px;background:transparent;font-family:var(--display);font-size:14px;line-height:inherit;color:var(--muted);cursor:pointer}
.d1 .chips button.on{border-color:var(--amber);color:var(--text)}
@media(max-width:820px){.d1 .chips button{min-height:44px}}
/* Production controls the design doesn't draw (a post's Report): text links in the design's link style. */
.d1 .linkbtn{background:none;border:0;padding:0;min-height:0;font:inherit;font-size:15px;color:var(--muted);text-decoration:underline;text-decoration-color:var(--amber);text-underline-offset:.2em;cursor:pointer}
.d1 .linkbtn:hover{color:var(--amber)}
.d1 .report{margin-top:8px;font-size:15px}
@media(max-width:820px){.d1 .linkbtn{min-height:44px}}
.visually-hidden{position:absolute!important;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
${fonts}
.d1{${dark};--rule-strong:#626160}
@media (prefers-color-scheme: light){.d1{${light};--rule-strong:#8c8e91}}
html,body{background:#0d0f14}
@media (prefers-color-scheme: light){html,body{background:#f6f7f9}}
`;
// The grid override must come after the inline classes it overrides: move the 820 px block to the end.
fs.writeFileSync(out, head + css + '\n/* The design\'s inline styles */\n' + inline + '\n@media(max-width:820px){' + gridded.map((c) => '.d1 .' + c + '.' + c).join(',') + '{grid-template-columns:1fr!important}}\n');
console.log('wrote', out, Object.keys(styles).length, 'inline classes,', gridded.length, 'grids');
