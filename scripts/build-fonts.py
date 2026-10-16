"""Builds fonts/day-one-serif-italic.woff2 from fonts/source-serif-4-italic.woff2 (RK14, SF2).

The italic is used for a few words per page (citations, a sign-off, review notes), yet the variable file carries
every weight and optical size: 127 KB. This keeps one weight (400) at one optical size (18, the body size) and every
character of the original, which comes to about 20 KB.

The SIL Open Font License 1.1 lets us modify the font, but a Modified Version may not use the Reserved Font Name
("Source", per fonts/OFL-source-serif-4.txt). So the new file is renamed "Day One Serif" everywhere a name is shown,
keeps Adobe's copyright notice and the license, and says what it was derived from. styles.css uses the same new name
for the family, and the regular face of that family is the unmodified Source Serif 4 file.

Usage (fontTools 4.65.0 with brotli): python3 scripts/build-fonts.py [output path, default fonts/day-one-serif-italic.woff2]
The output is the same bytes every time for the same fontTools version (no timestamps). test/fonts.test.js checks
the result: no variation tables left, no Reserved Font Name in its names, every character of the original kept.
"""
import os
import sys

from fontTools.ttLib import TTFont
from fontTools.varLib import instancer

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
SRC = os.path.join(ROOT, 'fonts', 'source-serif-4-italic.woff2')
OUT = os.path.join(ROOT, 'fonts', 'day-one-serif-italic.woff2')
FAMILY = 'Day One Serif'
WEIGHT = 400
OPSZ = 18

# Name IDs that hold names a person sees or a system matches on; none may keep "Source".
RENAMED = {
    1: FAMILY,                              # family
    2: 'Italic',                            # subfamily
    3: '1.000;DOG;DayOneSerif-Italic',      # unique ID
    4: FAMILY + ' Italic',                  # full name
    6: 'DayOneSerif-Italic',                # PostScript name
    16: FAMILY,                             # typographic family
    17: 'Italic',                           # typographic subfamily
}
DROP = (18, 21, 22, 25)  # compatible full name, WWS names, variations prefix: not needed once the font is static
NOTE = ('Day One Serif Italic is a Modified Version of Source Serif 4 Italic by Adobe, made by ChiefOS, Inc. for '
        'dayonegreat.com: one weight (400) at one optical size (18). Licensed under the SIL Open Font License 1.1.')


def main():
    font = TTFont(SRC, recalcTimestamp=False)
    font = instancer.instantiateVariableFont(font, {'wght': WEIGHT, 'opsz': OPSZ}, updateFontNames=False)
    for t in ('STAT', 'fvar', 'gvar', 'avar', 'HVAR', 'MVAR'):
        if t in font:
            del font[t]
    name = font['name']
    name.names = [n for n in name.names if n.nameID not in DROP and n.nameID < 256]
    for nid, value in RENAMED.items():
        name.removeNames(nameID=nid)
        name.setName(value, nid, 3, 1, 0x409)
        name.setName(value, nid, 1, 0, 0)
    name.removeNames(nameID=10)
    name.setName(NOTE, 10, 3, 1, 0x409)
    font['OS/2'].usWeightClass = WEIGHT
    for rec in name.names:
        if rec.nameID in (1, 2, 3, 4, 6, 16, 17) and 'Source' in rec.toUnicode():
            sys.exit('Reserved Font Name left in name ID %d' % rec.nameID)
    font.flavor = 'woff2'
    out = sys.argv[1] if len(sys.argv) > 1 else OUT
    font.save(out)
    print('wrote', out, os.path.getsize(out), 'bytes')


if __name__ == '__main__':
    main()
