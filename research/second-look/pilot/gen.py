"""Second Look data pilot: an open model (IBM Granite 3.3 2B Instruct, Apache-2.0, run locally with llama.cpp) writes
variations of comments that PEOPLE labelled (UCI YouTube Spam Collection, CC BY 4.0). Each variation keeps its seed's
human label; no label comes from an AI. Seeds come only from the training videos (01 to 03); videos 04 and 05 are the
untouched test set. Claude writes this script and the instruction below; the open model writes every case."""
import csv, json, random, re, sys, time
from llama_cpp import Llama

SEEDS_PER_CLASS = int(sys.argv[1]) if len(sys.argv) > 1 else 100
VARIATIONS = int(sys.argv[2]) if len(sys.argv) > 2 else 2
random.seed(20261030)
rows = []
for f in ('Youtube01-Psy.csv', 'Youtube02-KatyPerry.csv', 'Youtube03-LMFAO.csv'):
    for r in csv.DictReader(open('data-yt/' + f, encoding='utf-8', errors='replace')):
        t = re.sub(r'<[^>]+>', ' ', r['CONTENT']).strip()
        if 10 <= len(t) <= 400:
            rows.append({'id': r['COMMENT_ID'], 'text': t, 'label': int(r['CLASS'])})
spam = [r for r in rows if r['label'] == 1]; ham = [r for r in rows if r['label'] == 0]
seeds = random.sample(spam, SEEDS_PER_CLASS) + random.sample(ham, SEEDS_PER_CLASS)

INSTRUCTION = {
    1: 'This comment was posted under a music video and a person marked it as spam (self-promotion, a link, or a request '
       'unrelated to the video). Write one new comment, by a different person, that is spam in the same way but worded '
       'differently. Use only made-up channel names and links on example.com. No real names, phone numbers or brands. '
       'Reply with the comment only.',
    0: 'This comment was posted under a music video and a person marked it as not spam (an ordinary reaction). Write one '
       'new comment, by a different person, that is an ordinary reaction in the same way but worded differently. No '
       'links, no real names. Reply with the comment only.',
}
llm = Llama(model_path='models/granite-3.3-2b-instruct-Q4_K_M.gguf', n_ctx=1024, n_threads=2, verbose=False, seed=20261030)
out = open('pilot/synthetic.jsonl', 'a')
t0 = time.time(); n = 0
for s in seeds:
    for v in range(VARIATIONS):
        r = llm.create_chat_completion(messages=[{'role': 'system', 'content': 'You write short, realistic example comments for testing a spam filter.'},
                                                 {'role': 'user', 'content': INSTRUCTION[s['label']] + '\n\nComment: ' + s['text']}],
                                       max_tokens=90, temperature=0.9, top_p=0.95, seed=20261030 + n)
        text = r['choices'][0]['message']['content'].strip().strip('"')
        out.write(json.dumps({'seed_id': s['id'], 'label': s['label'], 'variation': v, 'text': text,
                              'model': 'ibm-granite/granite-3.3-2b-instruct Q4_K_M (Apache-2.0)',
                              'seed_source': 'UCI YouTube Spam Collection (CC BY 4.0), human labels'}) + '\n')
        out.flush(); n += 1
        if n % 20 == 0: print(n, 'done', round(time.time() - t0), 's', flush=True)
print('finished', n, round(time.time() - t0), 's')
