# E20-R2 run sheet

The order of work on the study server, from the tip of `main`. The protocol is `docs/research/prereg/E20r-front-door-replication.md`, Amendment 2. The maintainer starts every step that reaches another host.

Set these first. `/srv/e20` is an example: use the server's real paths. `LISTS` holds the cohort lists, and the other files are the frozen lists:

```bash
export LISTS=/srv/e20/lists EXCLUDE=/srv/e20/exclusions.txt HOMEPAGE=/srv/e20/homepage-only.txt REMOVALS=/srv/e20/removals.txt PRIOR=/srv/e20/prior-optouts.txt
```

```bash
export COMMON="--registered E20R --lists $LISTS --exclude $EXCLUDE --homepage-only $HOMEPAGE --removals $REMOVALS --prior-optouts $PRIOR"
```

```bash
export R=bench/front-door/results
```

## 1. Preflight

```bash
npm ci
```

```bash
npm run e20r:preflight
```

This runs the tests, `npm run e20r:acceptance` and the self-test on this checkout, on loopback. All must pass.

## 2. Pilot

One live round, or two at most. Each round takes exactly 50 sites. Pick the block that matches what happened, and run it in order.

### Round 1, every time

```bash
node bench/front-door/replicate.mjs --pilot 50 --pilot-round 1 $COMMON
```

If its manifest has `finishedAt`, stopped or not, seal it. Exit 1 means the round failed, and the next steps still follow:

```bash
node bench/front-door/pilot-report.mjs $R/e20r-pilot-1/raw.jsonl --exclude $EXCLUDE --skip $REMOVALS --skip $PRIOR --seal
```

After a hard kill the manifest has no `finishedAt`: skip the seal. Then prune:

```bash
node bench/front-door/validation-sample.mjs prune $R/e20r-pilot-1
```

If prune refuses, the run stores a privacy miss: go to [A privacy miss](#a-privacy-miss). A person reads `pilot-report.json`. It gives selected, eligible, graded, 2xx, DNS-complete and each class per claim cohort. The automatic rule catches only a cohort with nothing usable, so the reviewer must also reject severe attrition in a cohort. Record the decision on a sealed round:

```bash
node bench/front-door/pilot-report.mjs --decide $R/e20r-pilot-1 --decision go --reviewer <who>
```

### One round: it was a go

```bash
cp $R/e20r-pilot-1/pilot-sites.txt /srv/e20/pilot-sites-all.txt
```

Then go to pass 2.

### Two rounds: round 1 failed or was a no-go

A failed round needs changed code, a changed protocol, or a note in its folder:

```bash
echo "<what went wrong and why it can't repeat>" > $R/e20r-pilot-1/pilot-explanation.txt
```

Its sites go on the dropped list whatever happened to it:

```bash
sort -u $R/e20r-pilot-1/pilot-sites.txt > /srv/e20/pilot-sites-round1.txt
```

```bash
node bench/front-door/replicate.mjs --pilot 50 --pilot-round 2 --pilot-dropped /srv/e20/pilot-sites-round1.txt $COMMON
```

```bash
node bench/front-door/pilot-report.mjs $R/e20r-pilot-2/raw.jsonl --exclude $EXCLUDE --skip $REMOVALS --skip $PRIOR --skip /srv/e20/pilot-sites-round1.txt --seal
```

```bash
node bench/front-door/validation-sample.mjs prune $R/e20r-pilot-2
```

```bash
node bench/front-door/pilot-report.mjs --decide $R/e20r-pilot-2 --decision go --reviewer <who>
```

Build the dropped list from both rounds. Then check that no site ran twice, which must print 0:

```bash
cat $R/e20r-pilot-1/pilot-sites.txt $R/e20r-pilot-2/pilot-sites.txt | sort -u > /srv/e20/pilot-sites-all.txt
```

```bash
cat $R/e20r-pilot-1/pilot-sites.txt $R/e20r-pilot-2/pilot-sites.txt | sort | uniq -d | wc -l
```

## After the stopped pass 2 (Amendment 3)

Pass 2 stopped at 188 of 7,031 sites. Work through this in order, with the new code deployed. Nothing here reaches another host until pilot round 2, which needs Amendment 3 adopted.

**1. Before any prune**, run the frozen detector over the original raw file. It writes the private `legacy-findings.json`, and prints counts only:

```bash
node bench/front-door/pilot-report.mjs --legacy-findings $R/e20r-pass2
```

Exit 1, or `reproducesStop: false`: the stop isn't reproduced. Amendment 3 doesn't apply. Purge, with the printed `purgeConfirm`:

```bash
node bench/front-door/validation-sample.mjs purge $R/e20r-pass2 --confirm <purgeConfirm>
```

**2.** Count what the new detector flags. It prints counts only:

```bash
node bench/front-door/pilot-report.mjs --replay $R/e20r-pass2/raw.jsonl
```

**3.** A person reads `findings` in `$R/e20r-pass2/legacy-findings.json`. It gives record order and field path, never text. That person opens only those records, on the server, with `<order>` from the report. Nothing goes to a chat, a ticket, a shared log or a hosted model:

```bash
grep '^{"pass":2,"order":<order>,' $R/e20r-pass2/raw.jsonl | less -S
```

A real address: purge as above. Amendment 3 doesn't apply.

**4.** A false fire: write what was checked in a private note, with no flagged text. Record the review. It binds to the legacy report:

```bash
node bench/front-door/pilot-report.mjs --privacy $R/e20r-pass2 --false-fire /srv/e20/false-fire-note.txt --reviewer <who>
```

**5.** Prune the stopped pass, and check it prints `"verified":true`:

```bash
node bench/front-door/validation-sample.mjs prune $R/e20r-pass2
```

**6.** Pilot round 2 is required, because the code changed. Run the two-round block above from "Its sites go on the dropped list", with an explanation in round 1's folder only if round 1 failed. The runner skips the stopped pass's sites itself.

**7.** Pass 3. It takes the dropped list of both rounds, and skips the 188 sites itself. It runs once:

```bash
node bench/front-door/replicate.mjs --pass 3 --pilot-dropped /srv/e20/pilot-sites-all.txt $COMMON
```

**8.** Set the run folder for every command in sections 4 and Failure recovery:

```bash
export RUN=$R/e20r-pass3
```

## 3. Pass 2

```bash
node bench/front-door/replicate.mjs --pass 2 --pilot-dropped /srv/e20/pilot-sites-all.txt $COMMON
```

To stop it between sites, for a complaint or anything else that can't wait:

```bash
touch ~/.penthera-e20r2-stop
```

## 4. After a whole pass

`RUN` is the run you are working on: `$R/e20r-pass3` under Amendment 3, as set above. Every command from here down uses it.

The order matters: the privacy report reads text the draw deletes.

```bash
node bench/front-door/pilot-report.mjs --privacy $RUN
```

```bash
node bench/front-door/validation-sample.mjs draw $RUN
```

The analysis takes pass 2 as `--pass1`, under Amendment 2. Its other inputs are private files whose hashes are frozen in the protocol:

```bash
node bench/front-door/analyze-r.mjs --pass1 $RUN/raw.jsonl --pass2 /srv/e20/pass1/raw.jsonl --e20 /srv/e20/e20/tranco/raw.jsonl /srv/e20/e20/yc/raw.jsonl --industries /srv/e20/industries.csv --e20-excluded /srv/e20/e20-health-excluded.txt --out analysis.json
```

## Failure recovery

Every failed run ends in a prune or a purge. A prune reads the file back and prints `"verified":true`. If it doesn't, the run isn't closed.

| What happened | Exit | Do this |
|---|---|---|
| Usage error | 2 | Fix the command. Nothing ran. |
| Refused by the gate | 3 | Read the reason. Nothing ran. |
| Something changed during the run | 4 | Do what the runner printed. Pilot: seal, then prune. Pass 2: prune. The run decides nothing. |
| Stopped: scrub miss, resolver failures, stop file, source address, signal | 5 | Do what the runner printed. Pilot: seal, then prune. Pass 2: prune, and report what ran as partial. |
| Hard kill, crash or full disk | none | Prune only. The run counts as interrupted. |
| Prune refuses, or the privacy report isn't clean | 3 or 1 | Stop. A person reviews the flagged fields first (below). |

```bash
node bench/front-door/validation-sample.mjs prune $RUN
```

### A privacy miss

This holds for a pilot round and for pass 3. For a pilot round, `export RUN=$R/e20r-pilot-<k>` first. A false fire must not cost the run, so nobody purges yet. If there is no privacy report yet, write it:

```bash
node bench/front-door/pilot-report.mjs --privacy $RUN
```

1. A person reads `flaggedFields` in `$RUN/privacy-report.json`. It names fields and counts, never text.
2. That person opens the flagged records on the server only. Nothing goes to a chat, a ticket, a shared log, the terminal scrollback of a shared session, or a hosted model.
3. A confirmed false fire: write what was checked in a private note, with no flagged text in it, then record it. The analysis reports it as a deviation.

```bash
node bench/front-door/pilot-report.mjs --privacy $RUN --false-fire /srv/e20/false-fire-note.txt --reviewer <who>
```

4. A real miss: purge, with the `purgeConfirm` code the report printed. Report a pass 2 as partial. A pilot round needs a seal first if it has a finished manifest, and pass 2 refuses it without a verified purge or a recorded false fire.

```bash
node bench/front-door/validation-sample.mjs purge $RUN --confirm <purgeConfirm>
```

- `purge` refuses without that code, the first 12 characters of the raw file's hash. The report's code holds until the file changes. After a prune, or for a crashed run with no report, take it from the file:

```bash
sha256sum $RUN/raw.jsonl | cut -c1-12
```

- `purge` deletes the whole per-site raw file and writes `purge-manifest.json` with the original hash and the disposition. It works on finished, partial, crashed and privacy-failed runs, and it can't be undone. The run can't be analyzed afterward. There is no field-level cleaning.
- A pruned or purged round's sites stay on the dropped list, and `pilot-sites.txt` stays in its folder.
- Pass 2 and pass 3 are never resumed or restarted. A new run needs a new registration.
- A complaint: `touch ~/.penthera-e20r2-stop`, prune, reply. Remove the stop file only once the reason is settled.
- A first SIGINT or SIGTERM ends the run after the visits in flight, up to 30 seconds. A second one kills it.
