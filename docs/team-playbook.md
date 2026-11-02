---
title: "How we run Penthera with a team of AI sessions"
sidebarTitle: "Team playbook"
description: "The setup behind Penthera: one lead chat, about ten role sessions, files as shared memory, and a check that can say no. With a starter prompt to copy."
---

> **Project page.** For "how do you build Penthera with AI agents, and how do I copy the setup?"

Penthera is built next to a PhD. For a week, one main chat and about ten role
sessions in Claude Code ran most of the work, on around 15 minutes a day of
the maintainer's time. This page is that setup, with a prompt you can paste
into your own main chat. It's a working method, not a product, and the limits
are at the end.

## The idea

You set the direction and keep the gates. One lead chat holds the overview,
splits the work and checks it. Role sessions each own one area. Files on disk
are the shared memory, because chats forget and get compacted.

Every piece of work has an owner, a definition of done and a checker who isn't
the owner. Lessons turn into checks, so the same mistake can't happen three
times.

## Five levels, and where this sits

A frame going around in November 2026: Prompt, Context, Harness, Loop, Graph.
Each level wraps the one below.

| Level | The model gets | In this setup |
|---|---|---|
| 1. Prompt | One sentence. You are the loop | Where every chat starts |
| 2. Context | The files, rules and decisions it needs | A one-page statement, a board, memory, role briefs, a lessons file |
| 3. Harness | Tools, how to call them, results fed back | Claude Code with skills and MCP servers |
| 4. Loop | It runs until the job is done, without you typing | Scheduled morning, evening and Monday runs; a CI loop that fixes a failing PR |
| 5. Graph | Which agents exist and what each hands to the next | Roles plus pipelines: the researcher hands a noise list to the programmer, a reviewer checks, the lead merges on the maintainer's go |

Two lessons from levels 4 and 5:

- **A loop needs a check that can say no.** Every loop here ends on something
  deterministic: tests, a gate, a recomputation, or a reviewer who isn't the
  owner. Without that, a loop repeats its mistakes faster. It's the same rule
  Penthera itself follows: rules decide, a model may only propose.
- **Most of the graph is still drawn by hand.** The lead routes the work in
  chat. That's flexible, but it costs attention. Hand-offs that repeat move
  into scripts and scheduled tasks. The gates stay with the maintainer.

## The building blocks

| Block | What it is |
|---|---|
| Core statement | One page: mission, ethos, what we never say. Only the maintainer changes it |
| Board | One page: where things stand, then the tasks in order |
| Operating system | Rhythm, who decides what, what happens in an incident |
| Role briefs and logs | One file per role: what it owns, then a log, newest first |
| Decision log | Every decision with the date, who made it and why |
| Heuristics | Lessons with evidence, promoted from lesson to heuristic to rule |
| Pipelines | Fixed loops for work that comes back: experiments, writing, releases, outside projects |
| Memory | Short facts the main chat loads every session |

If it isn't in a file, the team doesn't know it. A chat that restarts rebuilds
itself from the board, the logs and memory.

## The team

| Role | Owns |
|---|---|
| Lead | Overview, delegation, quality checks, the board, reporting to the maintainer |
| Co-founder | Strategy, positioning, a second opinion on big calls |
| Researcher | Studies, statistics, sources, benchmarks |
| Programmer | Code, fixes and tests, on its own branch |
| Product manager | What to build next, and why it matters to the user |
| Designer | Every visual. The brand files are the source of truth |
| Open-source maintainer | README, docs, changelog |
| Marketing and copy | Launch timing, listings, drafts of posts and letters |
| Internal security | Runs Penthera on its own repo and checks for leaks |
| Reviewer | Often a fresh subagent. Never the owner of the work |

Start smaller. Four or five roles are enough. Add one only when a kind of work
keeps coming back and nobody owns it.

- **Session or subagent.** A role session is a long chat with its own history,
  for an area that comes back every day. A subagent is a one-off helper for a
  check or a search you need answered now.
- **Give a reviewer the work, not your conclusion.** One unanchored reviewer
  found 11 blockers after every test had passed.
- **How the lead briefs a role:** the goal, the steps, the output file, "done
  when", who checks it, and what it may not touch, push or publish. The first
  line says what the task is, because that's what shows in the preview.
- **Reports go to the lead, and the lead checks them before passing them on.**
  More than once, a report said "done" and it wasn't.

## The rhythm

| When | Who | What |
|---|---|---|
| Every morning | Lead | Read the logs, update the board, give each role one task |
| During the day | Roles | Do the one task, then log it |
| Every evening | Reviewer | Check the day's work against the gates; failed work goes back on the board |
| Every morning | Maintainer | Read five lines, answer the decision queue |
| Monday | Lead | Scorecard, retro, next week's plan |
| Day 30 | Maintainer and lead | Keep, change or stop the whole setup |

One task per role per day. Every log entry has three lines:

```
## 2 Nov: task name
Result: what is now true, with the number or link.
Learned: one thing that should change how we work.
Next: what you'd do next.
```

## Who decides

The maintainer decides anything in their name, anything public, releases,
money, new accounts, talking to outside people, and changes to the rules. The
lead decides everything else and logs it.

Questions reach the maintainer once a day, in a queue. Only a live incident
interrupts. One decision at a time, a few options, one marked as recommended.
Nobody asks again what was already answered. And no role ever changes a line
the maintainer wrote: it flags its concern instead.

## The pipelines

- **Experiments.** The plan is written before anything is scored. Then a
  baseline, an independent recomputation, the build, at most three reruns on
  the development split, and one score on held-out data. Results get published
  either way, and false alarms count.
- **Writing.** Facts locked, then the medium, the author's voice, structure, a
  pass that removes AI patterns, grammar, and a claims check that no claim got
  stronger while polishing. Text comes before design. Polishing never removes a
  limit.

## Lessons that carry to any project

- Check a report before you pass it on.
- Say "not yet" and name what's missing. Never a hopeful "ready".
- Read a number from its source, not from memory. Our estimates were off by a
  factor of two.
- Review every fix again. One fix took four reviews.
- Prove a check can fail before you trust a clean result. One of our leak
  checks matched nothing for days.
- Compute a public number in one place. Two pages showed different counts for
  days.
- Every research result lists its limits: possible mistakes, where AI was used,
  and what a person checked.

A lesson seen once stays a lesson. Seen twice, or once at high cost, it becomes
a heuristic. Three times, or anything about safety, it becomes a rule enforced
by a test.

## Guardrails

- Private notes stay in a local folder that isn't in git. A leak check runs
  before anything leaves it.
- Nothing goes out without the maintainer's yes: posts, emails, pull requests,
  merges, releases.
- Side sessions never push. The lead opens one pull request per batch.
- Each experiment has a fixed budget cap.
- No claim stronger than the evidence. Every number traces back to a file.

## Start tomorrow

1. Write a one-page statement yourself: what you're building, for whom, and
   what you never claim.
2. Make a private folder, kept out of git: `STATEMENT.md`, `BOARD.md`,
   `team/decisions.md`, `team/HEURISTICS.md`. Set up a backup on day one.
3. Paste the starter prompt below into your main chat.
4. Let it draft your rhythm and one pipeline. Read them and approve them.
5. Start two or three role sessions with one task each. Add more after the
   first retro.

### Starter prompt

Copy this into your main chat and edit the parts in brackets.

```
You're the lead of a small team of AI sessions for [project]. I set the
direction and keep the gates; you split the work, brief role sessions, check
their output before you pass it on, and keep the board current.

Read STATEMENT.md and BOARD.md first. Files are our shared memory: the board,
team/decisions.md, one log per role with Result / Learned / Next, and
team/HEURISTICS.md for lessons with evidence.

Rules:
- Every task has an owner, a "done when", and a checker who isn't the owner.
- Every loop ends on a check that can say no: tests, a gate, a recomputation,
  or a reviewer who isn't the owner.
- Give a reviewer the work, not your conclusion.
- Ask me one decision at a time, with a few options and one marked
  (Recommended). Don't ask again what I already answered.
- Nothing public goes out without my yes: posts, emails, PRs, merges,
  releases. Role sessions never push; you open one PR per batch.
- Never edit a line I wrote; flag your concern instead.
- Private notes stay in a folder that isn't in git.
- Never claim more than the evidence shows. Every result lists its limits.

First task: draft team/OPERATING-SYSTEM.md (rhythm, roles, who decides what)
and one pipeline for the work that comes back most often. Then propose the
first three role sessions, each with one task.
```

## Limits

- This is one maintainer's setup over one week, not a measured method. The
  numbers above come from our own logs, and no one outside the project has
  checked them.
- The scheduled runs only work while the laptop is awake.
- Too many sessions at once costs context and checking time. Three or four
  writing sessions, each on its own files, was our limit.
- The setup costs attention too: briefing and checking take most of the
  maintainer's 15 minutes.

Penthera itself is an offline, rule-based security agent for your repo, your
dependencies and your AI tooling. If this page was useful, the
[repository](https://github.com/danoszz/penthera) is where the work happens.
