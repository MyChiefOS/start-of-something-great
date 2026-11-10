"""Makes the site's smaller font files (RISKS.md RK139 and RK14) from the originals first committed in ad229c1.

What it keeps is only what the site draws, so nothing on screen changes:
  * the characters: Basic Latin, Latin-1, and the punctuation and signs the pages use or members commonly type
    (CHARS below). The originals were already Google Fonts' Latin set; what goes is its fringe (combining accents,
    which the site doesn't store since db/validate.js normalises text to NFC; dotless i, Ă, spacing accents, two
    arrows and the division slash), which the next font in the CSS list draws instead, as before for anything else;
  * the axes: Bricolage Grotesque's width axis pinned at 100, its default (no CSS sets font-stretch or
    font-variation-settings), and the serif's weight axis cut to 400 to 900, the weights the CSS uses (nothing asks
    for less than 400; <strong> inside 600 text asks for 900). Bricolage keeps its whole weight axis: cutting it moved
    some advances by up to 2 units in 1,000, which could move a line break. The optical-size axes stay whole: the CSS
    sets font-optical-sizing: auto, so the browser uses them at every size;
  * every OpenType feature (kerning, marks, tabular figures for font-variant-numeric: tabular-nums, fractions).

Checked Nov 10 with HarfBuzz against the originals, at every 50 of weight and 14 (Bricolage) or 11 (serif) optical
sizes, with and without kerning, tabular figures and fractions: every advance, kerning pair and mark position is the
same; outlines move by at most 0.466 (Bricolage) and 0.5 (serif) units of 1,000 to the em, under a 30th of a pixel at
the largest optical size, from rounding the remaining variation data to whole units. For files with no outline change
at all, keep only the character subset: the limits {} for every font (about 12 KB less per page instead of 90).

License (SIL OFL 1.1; fonts/OFL-*.txt): a subset is a Modified Version. Bricolage Grotesque has no Reserved Font Name,
so it keeps its name. Source Serif 4 reserves "Source", so the subset is renamed "Day One Serif" everywhere in its
name table, keeping Adobe's copyright and trademark notices (name IDs 0 and 7) and the license (13, 14).

Run from the repository root: python3 tools/fonts/build.py   (needs fonttools and brotli: pip install fonttools brotli)
It checks each original's sha256 first, and writes byte-identical files on every run.
"""
import hashlib
import io
import subprocess
import sys

from fontTools.ttLib import TTFont
from fontTools.varLib import instancer
from fontTools import subset

SOURCE_COMMIT = 'ad229c1'
CHARS = [(0x20, 0x7E), (0xA0, 0xFF), (0x152, 0x153), (0x2002, 0x2002), (0x2009, 0x2009), (0x200B, 0x200B),
         (0x2013, 0x2014), (0x2018, 0x201A), (0x201C, 0x201E), (0x2022, 0x2022), (0x2026, 0x2026), (0x2032, 0x2033),
         (0x2039, 0x203A), (0x2044, 0x2044), (0x20AC, 0x20AC), (0x2122, 0x2122), (0x2212, 0x2212)]

FONTS = [
    # (original in SOURCE_COMMIT, its sha256, output, axis limits, new family name or None, style)
    ('fonts/bricolage-grotesque.woff2', 'a756882d8a7802ebd4663b4544a62ebedafc7227c1c159ab95eea61393af3f8e',
     'fonts/bricolage-grotesque.woff2', {'wdth': 100}, None, None),
    ('fonts/source-serif-4.woff2', 'f2ea9c12d2fe9bd3a9589b02ad2c0909da88f30938c91adc838c4f4098f9f9e0',
     'fonts/day-one-serif.woff2', {'wght': (400, 900)}, 'Day One Serif', 'Regular'),
    ('fonts/source-serif-4-italic.woff2', '96e6393209728ab93c334ae739af8a040cd2006c82e8614d6465a8084db88f89',
     'fonts/day-one-serif-italic.woff2', {'wght': (400, 900)}, 'Day One Serif', 'Italic'),
]


def original(path, sha):
    data = subprocess.run(['git', 'show', SOURCE_COMMIT + ':' + path], check=True, capture_output=True).stdout
    got = hashlib.sha256(data).hexdigest()
    if got != sha:
        sys.exit(path + ' at ' + SOURCE_COMMIT + ' has sha256 ' + got + ', expected ' + sha)
    return data


def rename(font, family, style):
    """Takes the Reserved Font Name out of every name the font presents, keeping the notices the license requires."""
    ps_family = family.replace(' ', '')
    keep = {0, 7, 13, 14}  # copyright, trademark, license description, license URL
    names = {1: family, 2: style, 3: ps_family + '-' + style + ';subset for dayonegreat.com', 4: family + ' ' + style,
             6: ps_family + '-' + style, 16: family, 17: style, 25: ps_family + style}
    table = font['name']
    for rec in list(table.names):
        if rec.nameID in names:
            table.removeNames(nameID=rec.nameID)
    for name_id, text in names.items():
        if name_id in (16, 17, 25):
            continue  # left out: family and style (1, 2) say it, and 25 is only for named instances' PostScript names
        table.setName(text, name_id, 3, 1, 0x409)
        table.setName(text, name_id, 1, 0, 0)
    for rec in table.names:
        if rec.nameID not in keep and 'Source' in rec.toUnicode():
            # The named instances' PostScript names (SourceSerif4Roman-Bold) and anything else that still says it.
            rec.string = rec.toUnicode().replace('Source Serif 4', family).replace('SourceSerif4', ps_family).replace('Source', 'Day One')


def build(src_path, sha, out_path, limits, family, style):
    font = TTFont(io.BytesIO(original(src_path, sha)), recalcTimestamp=False)
    font.flavor = None
    font = instancer.instantiateVariableFont(font, limits, updateFontNames=False)
    # Saved and read back before subsetting, as the command-line tools do between steps (the subsetter needs the
    # instanced font's tables complete, not as the instancer left them in memory).
    buf = io.BytesIO()
    font.save(buf)
    font = TTFont(io.BytesIO(buf.getvalue()), recalcTimestamp=False)
    opts = subset.Options()
    opts.layout_features = ['*']
    opts.name_IDs = ['*']
    opts.name_languages = ['*']
    opts.notdef_outline = True
    opts.recalc_timestamp = False
    opts.flavor = 'woff2'
    sub = subset.Subsetter(opts)
    sub.populate(unicodes=[c for lo, hi in CHARS for c in range(lo, hi + 1)])
    sub.subset(font)
    if family:
        rename(font, family, style)
    font.flavor = 'woff2'
    buf = io.BytesIO()
    font.save(buf, reorderTables=False)
    with open(out_path, 'wb') as f:
        f.write(buf.getvalue())
    print('%-34s %7d bytes  sha256 %s' % (out_path, len(buf.getvalue()), hashlib.sha256(buf.getvalue()).hexdigest()))


if __name__ == '__main__':
    for args in FONTS:
        build(*args)
