#!/bin/sh
# sh tools/design/all.sh <the handoff's static folder>: rebuilds every page in built.list from Aaron's design, then
# design.css and the shell, from the repository root. Running it on an unchanged tree changes nothing.
set -e
D="$1"
[ -f "$D/css/styles.css" ] || { echo "usage: sh tools/design/all.sh <design_handoff_day_one_great/static>"; exit 2; }
while read -r page target; do node tools/design/build.js "$D" . "$page" "$target" >/dev/null; done < tools/design/built.list
node tools/design/css.js "$D" . >/dev/null
node scripts/pages.js >/dev/null
node scripts/shell.js
