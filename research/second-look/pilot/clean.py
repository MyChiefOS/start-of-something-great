"""Quality checks on the open model's cases. Dropped, never fixed: refusals or notes about the task, empty or over 400
characters, a near-copy of its seed (most words the same), any link not on example.com, anything that looks like a
phone number or an email address. Reports how many each rule dropped. The label always stays the seed's (a person's)."""
import csv, json, re, collections
seeds = {}
for f in ('Youtube01-Psy.csv', 'Youtube02-KatyPerry.csv', 'Youtube03-LMFAO.csv'):
    for r in csv.DictReader(open('data-yt/' + f, encoding='utf-8', errors='replace')):
        seeds[r['COMMENT_ID']] = r['CONTENT']
words = lambda t: set(re.findall(r'[a-z0-9]+', t.lower()))
why = collections.Counter(); kept = []
for line in open('pilot/synthetic.jsonl'):
    s = json.loads(line); t = s['text'].strip()
    a, b = words(t), words(seeds.get(s['seed_id'], ''))
    if not t or len(t) > 400: why['empty or too long'] += 1; continue
    if re.search(r"\b(I'm sorry|I cannot|I can't|As an AI|Here is|Here's a|Sure[,!])", t, re.I): why['a refusal or a note about the task'] += 1; continue
    if a and b and len(a & b) / max(1, len(a | b)) > 0.8: why['a near-copy of its seed'] += 1; continue
    links = re.findall(r'(?:https?://|www\.)\S+|\b[a-z0-9-]+\.(?:com|net|org|ly|co|io)\b', t, re.I)
    if any('example.com' not in l.lower() for l in links): why['a link not on example.com'] += 1; continue
    if re.search(r'\d[\d\s().-]{8,}\d', t) or re.search(r'\S+@\S+\.\S+', t): why['a phone number or email address'] += 1; continue
    kept.append(s)
with open('pilot/synthetic-clean.jsonl', 'w') as f:
    for s in kept: f.write(json.dumps(s) + '\n')
print(json.dumps({'generated': sum(why.values()) + len(kept), 'kept': len(kept), 'dropped': dict(why),
                  'kept by label': dict(collections.Counter('spam' if s['label'] else 'not spam' for s in kept))}, indent=1))
