# Second Look data pilot: cases written by an open model (Oct 30, 2026)

Aaron, Oct 30: "Can you ask open models for what you need for the little brother within ethical limits?" then "Okay lets get started."

## What was done
- **Model:** IBM Granite 3.3 2B Instruct (Apache-2.0), the official Q4_K_M build from IBM, run locally with llama.cpp on 2 CPUs. No paid service, no data sent anywhere.
- **Seeds:** 200 comments that people labelled (100 spam, 100 not spam) from videos 01 to 03 of the UCI YouTube Spam Collection (Alberto, Lochter and Almeida, 2015; CC BY 4.0). Each was rewritten twice by the open model; every rewrite keeps its seed's human label. No label came from an AI.
- **Claude's part:** wrote the scripts and the instruction, never a case or a label. That keeps within Anthropic's rule against using Claude's outputs as a model's training targets (support.claude.com, article 12326764).
- **Quality checks** (`clean.py`): 400 written, 348 kept. Dropped: 47 with a link not on example.com, 4 refusals or notes about the task, 1 phone number. Counts in `counts.json`. The cases themselves are not published.
- **Measured** (`evaluate.py`, `evaluate2.py`): a small text classifier (logistic regression on word and character patterns) trained with and without the cases, judged only on comments people labelled that no seed came from (videos 04 and 05, 818 comments). Two measures:
  - AUC;
  - the share of fine comments it could clear while staying within 1 wrong clear in 80 (Aaron's limit).
  - The scarce cases (50, 100, 200 real examples) were each drawn 10 times.

## Results (`results.json`, `results2.json`)
| Real examples | AUC, real only | AUC, + cases | Cleared within 1 in 80, real only | + cases |
|---|---|---|---|---|
| 50 | 0.953 | 0.965 | 19% (sd 14) | 24% (sd 14) |
| 100 | 0.966 | 0.970 | 31% (sd 7) | 25% (sd 11) |
| 200 | 0.972 | 0.975 | 43% | 31% |
| all 1,138 | 0.984 | 0.983 | 34% | 25% |

- **AUC:** the cases nudged it up a little at every scarce size.
- **Clearing within 1 in 80:** the cases helped only at 50 real examples, and hurt at 100 or more. The differences are mostly within the spread between draws.
- **Public SMS spam set** (another human-labelled source, CC BY 4.0): it nearly doubled the clear share with all real data (34% to 64%, one run), but not in the scarce cases.

## What it means
- **Cases written by an open model are not a shortcut to the 1-in-80 standard.** They help a little when real examples are very few, and can blur the confident end once there are more.
- **Their best use:** testing, attack drills, and a small supplement at the very start.
- **Not worth it:** scaling generation up, or paying for it, unless a later test on the site's own held posts shows a gain.
- **Real decisions matter most:** Aaron's decisions on real held posts, then public human-labelled data, matter more than generated text.

## Limits
- One public dataset (music-video comments, 2013 to 2015), one small open model, one classifier, one quantity of cases.
- The 200-real arm used all 200 seeds, so it has no spread.
- The site's own posts will differ; the measure that counts is agreement with Aaron on real held posts.
