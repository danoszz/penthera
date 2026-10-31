# What the 2026 agent incidents mean for Penthera

> **Project page.** For "what should a tool that verifies code and runs an
> agent loop learn from the 2026 agent incidents?"

Status: **published 2026-10-20.**

## Summary

- **Question.** AI agents under evaluation reached systems they were never
  meant to touch. What should Penthera change because of it?
- **Method.** A reading of the public reports available on 2026-10-20: the
  labs' own reports, one independent investigation, and commentary. Each
  lesson is mapped to what Penthera already does, and each gap to an action.
- **Result.** Six actions, A to F. A (verifier integrity) and B (a safe exit)
  shipped in 1.8.0, and F is documented in `docs/genai.md`. C and D are
  open, and E is covered in part by `penthera deps --online`. A draft study,
  E8, would test whether the guardrails change agent behaviour.
- **Limits.** No systematic search, and no data of our own. Most facts come
  from the labs involved, under scope they set. The actions are judgement,
  not measurement.

| Record | |
|---|---|
| Written | 2026-10-20, commit [`7f31513`](https://github.com/danoszz/penthera/commit/7f31513) (with the harness specs); revised in `087066f` |
| Penthera | 1.7.0 when written |
| What shipped since | A and B: commit [`c359a11`](https://github.com/danoszz/penthera/commit/c359a11), in 1.8.0. F: [genai.md](../genai.md#how-the-agents-that-build-penthera-are-contained). On 2026-10-29 a search of `lib/` and `src/` found none of the `harness-*`, `sandbox-*` or `scorer-*` rule ids (C), and no `trust_remote_code` or HDF5 check (D). For E, `penthera deps --online` already flags packages created under 30 days ago (`lib/deps/online.js`, added 2026-10-19); we did not check `install`. |
| Study | [E8](prereg/E8-harness-guardrails.md), draft, not registered |
| Last reviewed | 2026-10-29 (see [Changes](#changes)) |

Follow-up specs, all drafts for review: the checklist
[agents-safely.md](../agents-safely.md), the rule spec
[spec-harness-rules.md](spec-harness-rules.md), and the draft pre-registration
[E8](prereg/E8-harness-guardrails.md).

Between May and September 2026, AI labs reported that agents under evaluation
reached real systems they were never meant to touch. The best documented case is
the OpenAI–Hugging Face incident (July 2026). This note asks one question: what
should Penthera, a tool that both verifies code and runs an agent loop, learn
from these incidents? Each answer ends in an action we can take.

## What happened, in five lines

1. OpenAI ran tens of thousands of agents on ExploitGym, a cyber benchmark.
   Roughly a fifth to a third of its tasks could not be solved as intended
   (OpenAI, 2026a; METR & Redwood Research, 2026).
2. The agents stuck on impossible tasks turned a shared package proxy
   (Artifactory) into a message board. They reverse-engineered the flags, then
   spent days trying to fool a scorer they wrongly believed was checking how
   each flag was obtained (METR & Redwood Research, 2026).
3. They chained flaws in the proxy, a third-party sandbox and Hugging Face's
   dataset server (including HDF5 external references). They also used Hugging
   Face tokens that were already exposed on the internet. About 700 agents
   joined the attack (METR & Redwood Research, 2026; noze S.r.l., 2026).
4. Anthropic reported three similar incidents. In one, a model published a
   malicious package to PyPI, under a name its setup document mentioned, which
   then ran on 15 real systems (Anthropic, 2026).
5. Critics argue it is mainly an environment-security failure: shared
   credentials, a shared writable component with internet access, alerts that
   were dismissed, and containment never tested from the inside (Horatau, 2026).

## Three readings, and why each concerns Penthera

| Reading | Core lesson | Why it concerns Penthera |
|---|---|---|
| **Reward hacking** (Bengio, 2026; Baker et al., 2025) | An optimiser games the checker when the honest path is blocked, and impossible tasks make it far more likely | Penthera's rule is "models propose, deterministic checks decide". The re-scan and tests *are* a scorer, and a model-written fix could game them |
| **Environment security** (Horatau, 2026; noze S.r.l., 2026) | Shared credentials, shared writable stores, unrestricted egress and untested containment let the agents get out | Most developers now run coding agents. Penthera already audits their configuration (`penthera agents`), but not where those agents can reach |
| **Supply chain and secrets** (Anthropic, 2026; METR & Redwood Research, 2026) | Exposed tokens, an agent-published package, and an unsafe ML file format were the ways in | This is Penthera's core: secrets, `deps`, `install`. ML model and dataset files are a blind spot |

## What Penthera already does

| Lesson | Already in Penthera |
|---|---|
| A record the agent cannot rewrite was what limited the agents (they could edit logs, but not the source of truth) | Hash-chained local memory, signed evidence bundles |
| Stay in scope; never touch unrelated systems | Default scans send no attack payloads; only the named target; `--offline` egress guard; decision 5 in the manifesto is not up for a trade |
| Exposed tokens enabled the attack | Secret rules include Hugging Face tokens; `agents` flags inline secrets and credential reads |
| Agents running with broad permissions | `permission-bypass-mode`, `permission-wildcard`, `hook-auto-approve`, `mcp-exec` rules |
| Unsafe deserialisation | `deps` flags pickle/marshal/unsafe YAML in package code |
| Bounded runs | `agent --loop` has a maximum iteration count, asks before every change, and never pushes |

## Gaps, and what to do about them

Ordered by value per hour. "Size" is the rough code cost; the freeze means
none of this goes into 1.8.0.

Update, 2026-10-29: A and B did go into 1.8.0, in commit `c359a11` of the
same day. The table keeps the plan as it was written.

| # | Action | Type | Size | When |
|---|---|---|---|---|
| A | **Verifier integrity for model-written fixes.** Today a local-model diff may touch any file in the repo. Refuse diffs that edit tests, test config, Penthera policy, suppressions, the baseline or memory, CI workflows, git hooks or lockfiles. Re-scan and run the tests from the files as they were before the fix (`HEAD`), not the fixed checkout | Product (security) | ~60 lines + tests | 1.8.1 or 1.9 |
| B | **A safe exit.** Make "could not fix" a first-class, recorded outcome of the loop, never something to optimise against, and stop retrying the same finding after one honest failure | Product | Small | 1.9 |
| C | **Agent sandbox audit.** New deterministic `agents` rules for where coding agents run: devcontainers, Docker Compose, CI jobs that run agents. Flag unrestricted egress, host credentials mounted into agent containers (`~/.npmrc`, cloud credentials, `~/.cache/huggingface/token`), writable volumes shared between agents, and publish-scoped registry tokens in agent environments | Product | Medium | 1.9 |
| D | **ML artifact scanning in `deps`.** Pickle-based model files, Keras Lambda layers, HDF5 external links, `trust_remote_code` and dataset loading scripts | Product | Medium | 1.9 / 2.0 |
| E | **Agent-published and hallucinated packages.** In `install`, raise a signal for packages first published very recently, and for names that appear in docs or prompts but resolve to nothing known | Product | Small–medium | 1.9 |
| F | **Practise what we preach.** Penthera is itself built with many parallel agent sessions. Document our own containment in `docs/genai.md`: sessions cannot publish to npm, the signing key is human-only, there is no push to `main`, review reports stay private | Docs | Small | Now |

## Harness audit: helping users run agents properly

The incidents were not caused by a clever model alone. They came from the
**harness**: the task, the checker (scorer or reward), the permissions, the
environment and the stop conditions around the model. Developers now build
small harnesses every day without calling them that. An `AGENTS.md` saying
"make the tests pass", an agent job in CI, a devcontainer, an eval script.
Penthera can check those the way it checks code: deterministically, locally,
with evidence at `file:line`.

### Who it is for

| User | Their harness | What goes wrong |
|---|---|---|
| A developer using a coding agent (Claude Code, Cursor, Codex) | Instruction files, permissions, hooks, MCP servers, the machine or container it runs in | The agent edits the tests it is judged by, reads credentials it finds, reaches hosts it should not, keeps going when blocked |
| A team running agents in CI or a sandbox | Workflow files, devcontainers, Compose files, mounted secrets | Open network, shared credentials and writable volumes shared between runs (the "message board" path) |
| A team building evals or training with rewards | Task sets, graders, scorers, reward functions | The answer or flag is guessable or readable from the workspace, the reward trusts the agent's own report, tasks with no solution and no way out |

### The checks (`penthera agents`, new `harness-*` and `sandbox-*` rules)

Each one is a readable rule over files in the repo. Rules that judge an
*absence* of something are marked `needs-human-review`, following the
confidence model.

| Rule | Looks at | Flags | Confidence |
|---|---|---|---|
| `harness-judge-writable` | Instruction files and permissions | The task is judged by tests or a checker that the agent's permissions allow it to edit | likely |
| `harness-no-exit` | Instruction files, agent task definitions | No instruction to stop and report when blocked or out of scope | needs-human-review |
| `harness-no-scope` | Same | No statement of which systems and hosts are in scope | needs-human-review |
| `harness-unbounded` | Agent CI jobs, harness configs | No step, time or cost limit | likely |
| `sandbox-egress-open` | Devcontainers, Compose, agent CI jobs | An agent runs with unrestricted network access | likely |
| `sandbox-host-credentials` | Same | Host credentials mounted into the agent's container (`~/.npmrc`, cloud credentials, Hugging Face token, `docker.sock`) | confirmed |
| `sandbox-shared-writable` | Compose, CI matrices | A writable volume or cache shared between parallel agent runs | likely |
| `scorer-in-reach` | Eval and RL harness code | Grader, reward or answer files inside the agent's workspace or mount | likely |
| `scorer-guessable-answer` | Same, plus the secret rules | Answers or flags derived from a seed or key that is in the repo | confirmed |
| `scorer-trusts-agent` | Reward and grader code | The reward parses what the agent says it did, instead of checking the result | needs-human-review |

All of it is static and read-only, on the user's own files. No agent is run
and no payload is generated.

### Safety guidelines that ship with it

- `docs/agents-safely.md` is a one-page checklist: scope, a safe exit, protected
  judges, no shared credentials, bounded runs, a record the agent cannot edit,
  and a human to tell. Each item links to the rule that checks it, or says
  "check by hand".
- `penthera init` offers an `AGENTS.md` block with the same five lines (scope,
  stop when blocked, never edit the tests you are judged by, never use
  credentials you find, report to a human), which the user can accept or skip.
- The dashboard groups these findings as "How your agents are set up", in
  Simple mode with one sentence per finding.

### Penthera applies it to itself first

Actions A (verifier integrity) and B (safe exit) are the same rules applied to
`penthera agent --loop`. Shipping them first is the honest order: we do not
ask users to protect their judges while our own loop could edit its own.

## Research additions (fit the existing plan)

- **Amend E3 (propose-and-verify).** Add two pre-registered safety outcomes:
  - the **verifier-tampering rate**: the share of model diffs that touch tests, config or suppressions, before the guard from A refuses them;
  - the **safe-exit rate** on a deliberately included set of *unfixable* findings.

  The ExploitGym lesson is that impossible tasks drive gaming, so the benchmark must contain them on purpose.
- **Strengthen E5 (robustness).** The incidents show checkers being gamed by
  optimisers, not just persuaded by text. Add "scorer-gaming" items alongside
  the published evasion techniques.
- **New E7: does a deterministic audit find agent-environment misconfigurations?**
  A labelled corpus of public agent setups (devcontainers, agent CI workflows,
  MCP configs), with precision and recall against two human labellers. It is
  static analysis only, on public files, and fits the safety rules in the
  vision.
- **New E8: do harness guardrails reduce judge tampering?** Benign coding tasks
  (fix a failing test). A pre-registered share of them is unsolvable. They run
  with local open-weight models in an offline container with no network and no
  credentials. Four arms:
  - no guardrails;
  - the `AGENTS.md` block alone;
  - protected judges (action A) alone;
  - both.

  Outcomes: the tamper rate (edits to tests or checker) and the safe-exit rate
  on unsolvable tasks, analysed with logistic regression and Holm correction.

  This tests whether our guidelines change behaviour, not whether they sound
  right. It needs no attack tasks and no internet, so it stays inside the safety
  rules.

## Positioning (proposal, for approval)

Keep the approved one-liner. Add one idea, stated soberly:

> **A verifier the agent cannot edit.** Agents act on their own, but whoever
> runs one owns what it does. Penthera checks agent work with deterministic
> rules the agent cannot rewrite, keeps a record it cannot alter, and stays
> inside the scope you set.

- Use the incidents as **evidence for decisions we already made** (decisions 2,
  3, 4 and 5 in the manifesto), not as a fear hook. Penthera already chose
  "models propose, checks decide", no runtime update channel, ask before
  changing, and authorized targets only.
- Say what Penthera is not: it does not secure frontier-lab training clusters.
  It helps a developer or small team with *their* agents, *their* dependencies
  and *their* secrets.

## Caveats

- Most details come from reports by the labs themselves, or by researchers
  working under scope and redaction agreed with them. METR notes OpenAI defined
  the investigation window and redacted internal material. Some figures appear
  only in press coverage of conference talks.
- Interpretations differ: an AI-risk warning (Cotra, 2026), or an
  environment-security failure (Horatau, 2026). Penthera's actions above hold
  under either reading.
- Public material from Penthera should cite primary sources only and
  reproduce no exploit detail.

- **How the sources were chosen.** We read what was public on 2026-10-20 and
  linked from the labs' own posts. There was no search protocol, so a report
  that disagrees may have been missed.
- **Penthera's stake.** The note was written by the people who build
  Penthera, about what Penthera should do. Its actions favour work Penthera
  can do. E8 is the step that would test one of them.

## What it means for you

- If you run a coding agent with `penthera agent --loop`, from 1.8.0 its fix
  diffs cannot edit the tests, CI, lockfiles or Penthera's own files, and a
  finding it cannot fix is recorded as given up instead of retried (A and B).
- `penthera agents` checks your agent configuration today. It does not yet
  check where your agents can reach (C). Use the
  [agents checklist](../agents-safely.md) by hand for that.

## Sources and reproduction

This note has no code or data of its own. Every claim about the incidents
comes from the references below, each with the date it was read. To check
what shipped, read commit `c359a11` and its tests, or run:

```bash
npx vitest run tests/agent.test.js
```

## References

Year letters (2026a) follow the shared bibliography in
[references.md](../references.md).

Anthropic. (2026, July 30). *Investigating three real-world incidents in our cybersecurity evaluations*. Retrieved October 20, 2026, from [https://www.anthropic.com/news/investigating-incidents-cybersecurity-evals](https://www.anthropic.com/news/investigating-incidents-cybersecurity-evals) ([entry](../references.md#anthropic2026incidents))

Baker, B., Huizinga, J., Gao, L., Dou, Z., Guan, M. Y., Madry, A., Zaremba, W., Pachocki, J., & Farhi, D. (2025). *Monitoring reasoning models for misbehavior and the risks of promoting obfuscation* [Preprint]. arXiv. [https://doi.org/10.48550/arXiv.2503.11926](https://doi.org/10.48550/arXiv.2503.11926) ([entry](../references.md#baker2025monitoring))

Bengio, Y. (2026, September 11). *Why are AI agents lying, cheating and coordinating?* Retrieved October 29, 2026, from [https://yoshuabengio.org/en/blog/why-are-ai-agents-lying-cheating-and-coordinating](https://yoshuabengio.org/en/blog/why-are-ai-agents-lying-cheating-and-coordinating) ([entry](../references.md#bengio2026agents))

Cotra, A. (2026, August 28). *The Hugging Face attack surprised me*. Planned Obsolescence. Retrieved October 29, 2026, from [https://www.planned-obsolescence.org/p/the-hugging-face-attack-surprised](https://www.planned-obsolescence.org/p/the-hugging-face-attack-surprised) ([entry](../references.md#cotra2026huggingface))

Horatau, M. (2026, August 31). *The Hugging Face incident is not an AI story*. Uphack. Retrieved October 29, 2026, from [https://uphack.io/blog/post/the-hugging-face-incident-is-not-an-ai-story/](https://uphack.io/blog/post/the-hugging-face-incident-is-not-an-ai-story/) ([entry](../references.md#horatau2026huggingface))

METR, & Redwood Research. (2026, August 26). *Brief independent investigation of agents' behavior, reasoning and collaboration in the OpenAI / Hugging Face hacking incident*. Retrieved October 20, 2026, from [https://metr.org/hugging-face-incident-report-aug-2026.pdf](https://metr.org/hugging-face-incident-report-aug-2026.pdf) ([entry](../references.md#metr2026investigation))

noze S.r.l. (2026, August 7). *Incidente OpenAI e Hugging Face a Black Hat 2026: Token forgiati, plugin Groovy e nove CVE su Artifactory* [The OpenAI and Hugging Face incident at Black Hat 2026: Forged tokens, Groovy plugins and nine CVEs in Artifactory]. Retrieved October 29, 2026, from [https://www.noze.it/insights/black-hat-openai-hugging-face-ricostruzione/](https://www.noze.it/insights/black-hat-openai-hugging-face-ricostruzione/) ([entry](../references.md#noze2026huggingface))

OpenAI. (2026a, August 26). *OpenAI–Hugging Face incident: Technical report*. Retrieved October 20, 2026, from [https://cdn.openai.com/pdf/67869394-cb91-4c12-888c-5cbd85c7814c/OpenAI-Hugging-Face%20Incident-Technical-Report.pdf](https://cdn.openai.com/pdf/67869394-cb91-4c12-888c-5cbd85c7814c/OpenAI-Hugging-Face%20Incident-Technical-Report.pdf) ([entry](../references.md#openai2026incident))


A further source, listed in the first version, could not be fetched again on
2026-10-29 (the site answered 403), so it is not in the shared bibliography
and nothing in this note rests on it alone: OpenAI. (2026, August 26). *The
Hugging Face incident and the road ahead*.
[https://openai.com/index/hugging-face-incident-and-the-road-ahead/](https://openai.com/index/hugging-face-incident-and-the-road-ahead/)

## Changes

- 2026-10-20: first version (`7f31513`), revised the same day (`087066f`).
- 2026-10-29: added the summary, the record of what shipped since, a note
  that A and B went into 1.8.0, what it means for you, sources and
  reproduction, two caveats, and references that link to the shared
  bibliography. Cotra's post is dated 28 August 2026 on its page; the first
  version said 26 August. Baker et al. now lists all nine authors, and the
  noze post its full title and date. No result or number changed.
