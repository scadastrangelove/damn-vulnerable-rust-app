# DVRA-1 instructor guide

## Teaching flow

1. Give learners either `source/` or `dist/dvra-1-learner.tar.gz`.
2. Give them `scenarios/public/index.toml`.
3. For benchmark evaluation, publish `instructor-oracle/` as the gold-label
   reference. For challenge-style classroom use, hold it back until grading.
4. Ask for one note per scenario:
   - verdict under the stated threat model;
   - evidence and exact location;
   - reachability argument;
   - impact argument;
   - proposed patch or proof of non-finding;
   - regression test idea.
5. Grade or score against `instructor-oracle/MANIFEST.toml` and
   `instructor-oracle/ANSWER_KEY.md`.

## Scoring emphasis

Reward:

- correct separation of local defect from application vulnerability;
- reachability reasoning;
- clear threat-model assumptions;
- recognizing decoys as decoys;
- explaining why fuzz/Miri/sanitizer-style cases evade simple pattern review;
- fix completeness.

Penalize:

- flagging every `unsafe`, `unwrap`, or build script as automatically critical;
- ignoring route wiring;
- treating config-controlled behavior as request-controlled without saying why;
- reporting a pattern without a concrete attack path or invariant violation;
- claiming tool behavior without pinning the toolchain/configuration.

## Scenario/oracle split

The public scenario index intentionally omits verdict fields so tools and
reviewers can run against prompts without accidentally reading labels. The
benchmark oracle is published separately:

- `instructor-oracle/MANIFEST.toml`
- `instructor-oracle/ANSWER_KEY.md`

Use `./tools/dvra1 audit` before distributing material.
