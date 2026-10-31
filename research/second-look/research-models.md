# Second Look: model, data and placement research

Research for Aaron's decision of Oct 30, 2026 (harness/FACTS.md row 193): Second Look **decides within limits** (it may only clear a post JEVs held; everything else stays for Aaron), it is "a very very little LLM", and it learns only from Aaron's decisions and public human-labelled data, never from Claude's outputs.

Date: 2026-10-30. Labels: **verified** (what I checked, and how), **inferred** (from what), **unknown**. Measurements are from this sandbox (2 vCPU Intel Xeon 2.8 GHz, Node 22.22.0), not from Vercel or Supabase.

---

## 0. Bad news and findings against the plan (first)

1. **Second Look can't safely clear anything yet, and won't for some time.** To show that its clears are wrong at most 1% of the time (95% confidence), it needs about **300 of Aaron's decisions on held posts**, with no false clear at the chosen threshold. In my experiment, 100 calibration labels gave **zero clears in 20 of 20 runs**, even at a looser 2% target (verified: section 3). The site has 1 post today (stated in the brief), so Second Look runs in shadow mode for an unknown time. Public datasets can't stand in for these labels: they come from different sources, which breaks the assumption the guarantee relies on (inferred from the conformal method's exchangeability requirement, section 3).
2. **Push-back: "a very very little LLM" isn't the honest fit.** The smallest generative model I tested, SmolLM2-135M, took **1.23 s and about 800 MB per decision** (verified here). Fine-tuning it needs far more labels than exist, and the published evidence shows fine-tuned small classifiers beat zero-shot generative models on classification. The honest "very little" model is a logistic regression over JEVs's scores plus character n-grams: kilobytes to about 1 MB, sub-millisecond, plain JavaScript, with no pretrained weights and so no lineage question. On public spam data it **matched MiniLM** (verified, section 3). It is a small language classifier, not an LLM, and Aaron should hear that plainly. If he wants an actual language model, MiniLM-L6 (Apache-2.0) is the smallest clean option.
3. **Conflict with a published promise.** privacy.html says our checks keep, for GitHub posts, "Never the text itself". Training on the text of GitHub posts would break that promise unless the page changes first. The site's own posts are stored, but training a model on them isn't disclosed. Public text that says "no AI decides" (llms.txt line 69, team.html line 76) describes JEVs and stays true for it; the Second Look text in llms.txt, team.html and privacy.html must change before it clears anything (FACTS row 193 already notes this).
4. **Exclude Qwen as a base.** Two secondary reports (Forkast, Sep 11, 2026; Better Stack) say Anthropic's threat report of Sep 10, 2026 names Alibaba's Qwen team for the largest Claude distillation campaign it has measured (151M exchanges, May to July 2026, for Qwen 3.5 to 3.7). **Inferred**: I couldn't open Anthropic's page from this session. Anthropic's Feb 23, 2026 post names DeepSeek, Moonshot and MiniMax (verified). Given Aaron's "no distillation" intent, use no base model from a named lab.
5. **Packaging is heavier than it looks.** A plain install of transformers.js 4.3.1 is **484 MB**: onnxruntime-node alone is 288 MB, because it carries every platform's binaries (verified, `du`). Vercel's standard limit is 250 MB. Linux x64 needs only 48 MB of it (verified, file listing), so excluding the other platforms' files fits (inferred). On Supabase Edge (256 MB memory, 2 s CPU per request), the same encoder on single-thread WASM took **1.5 s to load and 405 MB resident in Node** (verified here; Deno's numbers unknown). A transformer in the Supabase gate is unproven and likely over the limits (inferred).
6. **My own experiment has a flaw.** My threshold search kept going past failed tests before stopping, which isn't the strict fixed-sequence test. In some cells, 2 or 3 of 20 runs went over the target, where the guarantee allows at most about 1. Production must use the strict procedure, with a test that would catch this (section 3).
7. **Record gap, not a conflict:** charter section 2 doesn't yet carry Aaron's Oct 30 decision that Second Look "decides within limits". Only FACTS row 193 does.

---

## 1. Model options, smallest to largest

Sizes and licences: **verified** from the Hugging Face model API (`/api/models/<id>`: licence tag, parameter count), Oct 30. Latency: **verified** on this sandbox where shown, otherwise inferred. Platform limits: **verified** from vercel.com/docs/functions/limitations (updated Aug 24, 2026) and supabase.com/docs/guides/functions/limits.

| # | Option | Size | Licence / lineage | CPU latency per post | Vercel Node (250 MB, 2 to 4 GB) | Supabase Edge (256 MB, 2 s CPU, 20 MB bundle) | Fit |
|---|---|---|---|---|---|---|---|
| A | Logistic regression over JEVs scores + hashed char 2-5-grams (TF-IDF) | about 1 MB at 2^18 weights, much less pruned (inferred) | Our own code and weights; no third-party weights | under 1 ms (inferred: a sparse dot product; not benchmarked) | Yes, plain JS, no dependencies | Yes, plain JS | **Best start** |
| A2 | Small gradient-boosted trees over the same features | KB to a few MB (inferred) | Our own | under 1 ms (inferred) | Yes (trees as JSON, about 100 lines of JS to evaluate) | Yes | Option once labels number in the thousands; easy to overfit on little data (inferred) |
| B0 | potion-base-8M (Model2Vec static embeddings) | 7.6M params | MIT; distilled from bge-base (MIT), an open model, not Claude | not measured | Likely, as a lookup table (inferred) | Possibly; 30 MB float32 is over the 20 MB bundle, so fetch at runtime (inferred) | Cheap text prior; untested |
| B1 | Supabase built-in `gte-small` (`Supabase.ai.Session`) | 33.4M params (thenlper/gte-small) | MIT | unknown (not measured) | n/a | Built in, no package (verified, Supabase docs); only gte-small is supported | Unmeasured; worth one probe |
| B2 | all-MiniLM-L6-v2, int8 (q8) | 22.7M params, **23 MB file** | Apache-2.0; distilled from Microsoft's MiniLM (open, 2020 to 2021, before Claude existed: inferred from dates) | **37 ms native** ONNX, load 0.28 s, 175 MB resident; **163 ms on single-thread WASM**, load 1.5 s, 405 MB (verified) | Yes, if the other platforms' ORT binaries are excluded (inferred) | Risky: CPU and memory (see section 0 item 5) | **Upgrade path** |
| B3 | paraphrase-MiniLM-L3-v2 | 17.4M | Apache-2.0 | about half of B2 (inferred) | Yes | Risky | Smaller variant |
| B4 | Ettin encoders 17m / 32m / 68m (JHU, 2025) | 17M to 68M (from the names; API gave no count) | MIT | unknown | Likely (inferred) | Risky | Modern alternative; ONNX export not checked |
| B5 | DeBERTa-v3-xsmall | about 70M total (not checked here) | MIT | unknown | Likely | Risky | Strong small encoder |
| B6 | ModernBERT-base | 149.7M | Apache-2.0 | about 4x B2 (inferred) | Yes, about 150 MB at q8 (inferred) | No | Too big for the data we have |
| x | TinyBERT_General_4L_312D | small | **No licence tag** (unknown) | | | | Excluded (licence unknown) |
| x | Llama-Prompt-Guard-2-22M | 70.8M total | Llama licence ("other"), gated | | | | Excluded (custom terms, gated access needs an account and acceptance) |
| x | protectai deberta-v3-base-prompt-injection-v2 | 184M | Apache-2.0, but trained on sets that include AI-generated conversations (its dataset tags) | | | | Usable only as an outside signal, never as a label source; not recommended |
| C1 | SmolLM2-135M-Instruct (generative) | 134.5M params, 131 MB q8 | Apache-2.0; pretraining included synthetic text (Cosmopedia, made by Mixtral; inferred from its public data list) | **1.23 s per decision** (about 200-token prompt, 3 new tokens), about 800 MB resident (verified) | Fits, slow | No | Poor fit |
| C2 | SmolLM2-360M | 361.8M | Apache-2.0 | more than C1 (inferred) | Fits | No | Poor fit |
| C3 | IBM Granite-4.0-350m | 352M | Apache-2.0 | unknown | Fits | No | Clean licence, still a generative model |
| C4 | Gemma 3 270M | 268M | Gemma Terms of Use, gated; distilled from larger Gemma (inferred) | unknown | Fits | No | Excluded (custom terms, gated) |
| x | Qwen3-0.6B, Qwen2.5-0.5B | 752M / 494M | Apache-2.0, but Qwen is the lab reported for Claude distillation (section 0 item 4) | | | | **Excluded** |
| x | SmolLM3-3B | 3.08B | Apache-2.0 | | Large functions beta only | No | Too big |

**Cost at 5,000 decisions a day** on Vercel (prices verified for iad1: $0.128 per active-CPU hour, $0.0106 per GB-hour, $0.60 per million invocations; per-decision CPU taken from this sandbox, so inferred to carry over; the project's region isn't checked):

- A: about $0.00 a month.
- B2 (MiniLM): about $0.40 a month.
- C1 (SmolLM2-135M): about $8 a month.

Supabase Pro includes 2M Edge Function invocations a month, then $2 per million (verified). The ChiefOS Vercel team is on Pro (FACTS row 36).

**Lineage, and whether "distilled from" matters.** Anthropic's terms bind outputs of Claude. A model distilled from another open model, such as MiniLM or Model2Vec, is governed by that model's licence. Both are permissive, and both predate Claude or come from non-Claude teachers (inferred). Option A has no pretrained weights at all, so it carries no lineage question.

**Anthropic's terms** (support.claude.com article 12326764, dated Mar 16, 2026; verified, read twice through the fetch tool, which paraphrases and wouldn't quote it whole):

- Prohibited: "Using Outputs as training targets for models".
- Permitted: "You can use Claude's Outputs to train models that don't compete with Anthropic's own models", including "Content categorization systems" and "Anomaly detection tools".
- The page doesn't say how those two lists relate.

Aaron's rule (no Claude outputs as labels) sits safely inside both readings. I'd extend it: Claude's outputs are used for no thresholds and no model choice, and Claude's simulated posts live only in software tests.

## 2. Public human-labelled datasets

Licences and sizes: **verified** from Hugging Face dataset cards and the API, UCI pages, and the original READMEs, unless marked otherwise.

**Usable (commercial use allowed, labelled by people):**

| Dataset | Size | Labelled by | Licence | Match to our case |
|---|---|---|---|---|
| SMS Spam Collection (UCI 228) | 5,574 texts, 747 spam | Spam extracted by hand from Grumbletext user reports; ham from the NUS SMS corpus and others | CC BY 4.0 (UCI page); attribution required | Low to medium: SMS from 2011 |
| YouTube Spam Collection (UCI 380) | 1,956 comments, 5 videos | The dataset's authors (manual labelling inferred) | CC BY 4.0 (UCI page) | **Medium, the closest**: public comments with self-promotion links |
| Civil Comments (google/civil_comments) | 1.8M comments | Jigsaw's added labels (crowd raters inferred) | CC0, text included | Medium, for abuse |
| Measuring Hate Speech (UC Berkeley D-Lab) | 100K to 1M rows | Crowdsourced | CC BY 4.0 | Low to medium. Unknown: the source platforms' terms (YouTube, Reddit, Twitter) |
| HateXplain | 19,229 posts | Crowdsourced | CC BY 4.0 | Low (Twitter and Gab) |

**Excluded, and why:**

- **Jigsaw Toxic (Kaggle):** the text is CC BY-SA 3.0, and the original download needs a Kaggle account and acceptance of rules (inferred). Civil Comments covers the same need.
- **SpamAssassin:** "Copyright for the text in the messages remains with the original senders".
- **Enron-Spam:** no licence found.
- **SecretBench:** needs a signed data-protection agreement and a Google Cloud account.
- **Samsung CredData:** 73,842 lines labelled by hand, but "Each file is under the existing project's license", and it holds real credentials. Keys stay deterministic in JEVs (J18).
- **Lakera gandalf_ignore_instructions:** selected with OpenAI's ada-002 embeddings, so its labels came from a model.
- **Lakera mosscap:** unlabelled.
- **deepset/prompt-injections:** no record of how it was made, and the card shows conflicting licences.
- **jackhhao/jailbreak-classification:** its benign class comes from OpenOrca and GPTeacher, which are GPT-generated.
- **ToxiGen:** machine-generated text.
- **RealToxicityPrompts:** Perspective API scores, which are model labels.
- **ealvaradob phishing, Deysi spam, zefang-liu phishing:** compilations with unknown upstream rights.
- **tdavidson hate_speech_offensive:** licence unknown.

**Gaps:** I found no clean, commercially licensed, human-labelled set for phishing, scams or prompt injection. That is a limit of this search, not proof that none exists. No public set matches "a post held on a small AI-and-agents community". Public data can give the text features a prior; only Aaron's decisions can calibrate.

## 3. How few labels are enough

**Literature:**

- **SetFit** (Tunstall et al., 2022, arXiv 2209.11055; verified). With 8 labels per class, it scored 88.5 on Customer Reviews, against 92.4 for full fine-tuning and 58.8 for standard fine-tuning on the same 8 labels. It beat GPT-3 on RAFT (71.3 vs 62.7) and trained in about 30 s.
- **Bucher and Martini (2024, arXiv 2406.08660; verified):** fine-tuned small models "consistently and significantly outperform" zero-shot GPT-4 and Claude Opus at classification.
- **Learn then Test** (Angelopoulos et al., 2021, arXiv 2110.01052; verified): finite-sample risk control for any model.
- **SCoRE** (Bai and Jin, arXiv 2603.24704; verified): selective "trust or abstain" decisions with the error among deployed predictions controlled. It needs only exchangeability, meaning the calibration posts and the live posts come from the same stream.

**Arithmetic (verified by calculation):** with zero false clears in n checked clears, the 95% upper bound on the false-clear rate is 1 − 0.05^(1/n), roughly 3/n.

| Target false-clear rate | Clears needed with no error |
|---|---|
| 1% | 300 |
| 0.5% | 600 |
| 0.2% | 1,500 |

**One reviewer:** Cohen's kappa needs two raters, so with Aaron alone the right measures are:

- Second Look's false-clear rate against Aaron's decisions, with its exact upper bound.
- Coverage: the share of the posts Aaron released that Second Look would have cleared.

The labels encode Aaron's policy, including his slips. His agreement with himself is unknown and can't be measured without showing him a post twice (inferred).

**My experiment** (verified; code and results in this folder: `bench/curve.py`, `data-sms/curve-results.json`):

- **Setup:** SMS Spam Collection; "clear" means ham; target is at most 2% false clears; 20 random splits per cell; two models, A (char n-gram logistic regression) and B (MiniLM embeddings + logistic regression).
- **100 calibration labels:** nothing was cleared, in every cell and for both models.
- **300 calibration labels:**
  - 20 training labels: about 25% of ham cleared (model A).
  - 100 training labels: about 67% cleared.
  - 1,000 training labels: about 93% cleared.
  - Average false-clear rate: 0.4% to 1.4%.
- **1,000 calibration labels:** 20 training labels already cleared 42 to 49%.
- **A against B:** the n-gram model matched or beat MiniLM in most cells.
- **Flaw:** see section 0 item 6.
- **Caveat:** SMS spam is an easy task, and our posts will differ.

## 4. What can be public, and what must not be

Public repository (MIT):

- the feature code, training code and evaluation protocol;
- the reason-code list;
- the model card (NIST AI RMF and the other standards Aaron named);
- the public datasets used, with the attribution CC BY requires;
- aggregate results with their bounds (counts and rates, never post text).

Private (database, row-level security, owner only):

- Aaron's labels (post ID plus decision);
- the calibration set;
- the threshold, kept private for the same reason as JEVs's thresholds: so it can't be gamed;
- the weights. Inferred reasons:
  - n-gram weights can reveal training text;
  - public weights let a spammer craft a post that clears.

Must not happen:

- text of GitHub posts kept for training without first changing privacy.html (Aaron's decision; a job for the planned legal review);
- training in a public repository's GitHub Actions job (inferred: public repositories' logs are public);
- Claude outputs used as labels, thresholds or model choice;
- anything run from Aaron's computer.

Training can run in a scheduled Vercel function (300 s, 2 GB; verified limits) that reads labels from the database and writes weights to a private table. Erasure is honoured at the next retrain, which takes seconds for model A (inferred).

## 5. Recommended starting design: Second Look v0

- **Model:** option A, L2-regularised logistic regression.
  - Features: JEVs's public question scores (J01 to J19, plus J16 and J17 on GitHub), hashed char 2-5-grams of the text, and a few counts (length, links).
  - Plain JavaScript, no dependency (the repository's package.json has one dependency, `postgres`), so it runs unchanged in Vercel Node and in the Supabase gate.
- **Output:** `clear` or `leave_for_aaron`, with a calibrated confidence and up to three reason codes, taken from the largest contributions and mapped to JEVs question IDs or "text resembles posts Aaron released".
- **Never clears** (deterministic, inferred design):
  - a key found (J18);
  - impersonation at 80 or more (J17);
  - a track record or brake (J10 above 0);
  - an open credible report (J14 above 0);
  - an appeal;
  - a scoring error.
- **Threshold:** a strict Learn-then-Test fixed-sequence test on Aaron's decisions about held posts, with α and δ his to set (1% at 95% needs 300 decisions). Until it passes, shadow mode only: it records what it would have done next to his decision.
- **After it passes:**
  - an audit sample of would-clear posts still goes to Aaron (rate his call, for example 5%);
  - an audited false clear switches auto-clear back to shadow and alerts him. It never blocks or locks anyone out, because Second Look can only release posts.
- **GitHub posts:** v0 uses scores and metadata only, so nothing changes the privacy promise until Aaron decides about text.
- **Upgrade:** add MiniLM-L6 embeddings in a Vercel function only once there are about 1,000 labels, and only if they beat v0 on Aaron's held-out decisions.

Sources: support.claude.com/en/articles/12326764; vercel.com/docs/functions/limitations; vercel.com/docs/functions/usage-and-pricing; supabase.com/docs/guides/functions/limits; supabase.com/docs/guides/functions/pricing; supabase.com/docs/guides/ai/quickstarts/generate-text-embeddings; technetexperts.com/vercel-onnxruntime-so-fix (Feb 14, 2026); npm registry (transformers 4.3.1, released Oct 6; onnxruntime 1.31.1); huggingface.co API and cards for every model and dataset named; archive.ics.uci.edu/dataset/228 and /380; spamassassin.apache.org/old/publiccorpus/readme.html; raw.githubusercontent.com Samsung/CredData, setu1421/SecretBench, MWiechmann/enron_spam_data; arxiv.org 2209.11055, 2406.08660, 2110.01052, 2603.24704; anthropic.com/news/detecting-and-preventing-distillation-attacks; forkast.news and betterstack.com on the Sep 2026 report.

```
Alignment
- Loop tier: full (1–5), since this decision is game-changing (an AI deciding, people's data, public text);
  steps actually run: 1 (research), 2 (simulation: benchmarks and the label-budget experiment), 4 (check against intent and decisions).
  Step 3 (fresh-agent review) and step 5 (sharing with Aaron) belong to the main session.
- Goals served: show AI can be trusted (clears only, with a stated error bound); narrow in-house AI; remove friction
  (fewer posts for Aaron); scale (about $0 at thousands of posts a day).
- Standing decisions touched: "high risk is held for Aaron" (Oct 16), changed by his Oct 30 "decide within limits"
  (in FACTS row 193, not yet in charter section 2); "Aaron moderates member posts" (unchanged: Second Look never removes);
  "checks alert, never lock out" (kept). Conflicts: privacy.html's "Never the text itself" if GitHub text is used
  (raised first); a push-back on "very very little LLM" (raised first).
- Fresh-agent review: not run by this sub-agent; needed before Aaron decides (full tier).
- Open for Aaron: decisions: (1) v0 as a non-LLM classifier, or insist on a language model; (2) the false-clear target
  and the audit rate; (3) whether to keep held-post text for training (a privacy change); (4) the never-clear list.
  Actions: none.
```
