# E20-R2 run sheet

The order of work, from the tip of `main` on the study server, then a detached checkout of the run's commit on the laptop. The protocol is `docs/research/prereg/E20r-front-door-replication.md`, Amendment 2 as changed by Amendment 3. Every command says where it runs, `[server]` or `[laptop]`. The maintainer starts every step that reaches another host.

On the server, the code is in `~/penthera` and the lists and notes are in `~/study`. Work from `~/penthera`, in `tmux`, so a dropped connection isn't a hangup. Set these first:

`[server]`

```bash
export LISTS=~/study/lists EXCLUDE=~/study/lists/exclusions-e20r.txt HOMEPAGE=~/study/lists/health-homepage-only.txt REMOVALS=~/study/removals.txt PRIOR=~/study/prior-optouts.txt
```

`[server]`

```bash
export COMMON="--registered E20R --lists $LISTS --exclude $EXCLUDE --homepage-only $HOMEPAGE --removals $REMOVALS --prior-optouts $PRIOR"
```

`[server]`

```bash
export R=bench/front-door/results
```

## 1. Preflight

`[server]` This must print `v22.23.4`. Record it. Use this same executable for `npm ci`, the preflight and every live command, in the `tmux` session that runs them. The command stops on any other version, and only then installs:

```bash
test "$(node -v)" = v22.23.4 && node -v | tee ~/study/node-version.txt && npm ci
```

`[server]`

```bash
test "$(node -v)" = v22.23.4 && npm run e20r:preflight
```

This runs the tests, `npm run e20r:acceptance` and the self-test on this checkout, on loopback. All must pass. A live start on any other Node version refuses with exit 3 before its first request.

## 2. Pilot

One live round, or two at most. Each round takes exactly 50 sites. Pick the block that matches what happened, and run it in order.

### Round 1, every time

`[server]`

```bash
node bench/front-door/replicate.mjs --pilot 50 --pilot-round 1 $COMMON
```

If its manifest has `finishedAt`, stopped or not, seal it. Exit 1 means the round failed, and the next steps still follow:

`[server]`

```bash
node bench/front-door/pilot-report.mjs $R/e20r-pilot-1/raw.jsonl --exclude $EXCLUDE --skip $REMOVALS --skip $PRIOR --seal
```

After a hard kill the manifest has no `finishedAt`: skip the seal. Then prune:

`[server]`

```bash
node bench/front-door/validation-sample.mjs prune $R/e20r-pilot-1
```

If prune refuses, the run stores a privacy miss: go to [A privacy miss](#a-privacy-miss). A person reads `pilot-report.json`. It gives selected, eligible, graded, 2xx, DNS-complete and each class per claim cohort. The automatic rule catches only a cohort with nothing usable, so the reviewer must also reject severe attrition in a cohort. Record the decision on a sealed round:

`[server]`

```bash
node bench/front-door/pilot-report.mjs --decide $R/e20r-pilot-1 --decision go --reviewer <who>
```

### One round: it was a go

`[server]`

```bash
cp $R/e20r-pilot-1/pilot-sites.txt ~/study/pilot-sites-all.txt
```

Then go to pass 2.

### Two rounds: round 1 failed or was a no-go

A failed round needs changed code, a changed protocol, or a note in its folder:

`[server]`

```bash
echo "<what went wrong and why it can't repeat>" > $R/e20r-pilot-1/pilot-explanation.txt
```

Its sites go on the dropped list whatever happened to it:

`[server]`

```bash
sort -u $R/e20r-pilot-1/pilot-sites.txt > ~/study/pilot-sites-round1.txt
```

`[server]`

```bash
node bench/front-door/replicate.mjs --pilot 50 --pilot-round 2 --pilot-dropped ~/study/pilot-sites-round1.txt $COMMON
```

`[server]`

```bash
node bench/front-door/pilot-report.mjs $R/e20r-pilot-2/raw.jsonl --exclude $EXCLUDE --skip $REMOVALS --skip $PRIOR --skip ~/study/pilot-sites-round1.txt --seal
```

`[server]`

```bash
node bench/front-door/validation-sample.mjs prune $R/e20r-pilot-2
```

`[server]`

```bash
node bench/front-door/pilot-report.mjs --decide $R/e20r-pilot-2 --decision go --reviewer <who>
```

Build the dropped list from both rounds. Then check that no site ran twice, which must print 0:

`[server]`

```bash
cat $R/e20r-pilot-1/pilot-sites.txt $R/e20r-pilot-2/pilot-sites.txt | sort -u > ~/study/pilot-sites-all.txt
```

`[server]`

```bash
cat $R/e20r-pilot-1/pilot-sites.txt $R/e20r-pilot-2/pilot-sites.txt | sort | uniq -d | wc -l
```

## After the stopped pass 2 (Amendment 3)

Pass 2 stopped at 188 of 7,031 sites. Work through this in order, with the new code deployed. Nothing here reaches another host until pilot round 2, which needs Amendment 3 adopted.

**1. Before any prune**, run the frozen detector over the original raw file. It writes the private `legacy-findings.json`, and prints counts only:

`[server]`

```bash
node bench/front-door/pilot-report.mjs --legacy-findings $R/e20r-pass2
```

Exit 1, or `reproducesStop: false`: the stop isn't reproduced. Amendment 3 doesn't apply. Purge, with the printed `purgeConfirm`:

`[server]`

```bash
node bench/front-door/validation-sample.mjs purge $R/e20r-pass2 --confirm <purgeConfirm>
```

**2.** Count what the new detector flags. It prints counts only:

`[server]`

```bash
node bench/front-door/pilot-report.mjs --replay $R/e20r-pass2/raw.jsonl
```

**3.** A person reads `findings` in `$R/e20r-pass2/legacy-findings.json`. It gives record order and field path, never text. That person opens only those records, on the server, with `<order>` from the report. Nothing goes to a chat, a ticket, a shared log or a hosted model:

`[server]`

```bash
grep '^{"pass":2,"order":<order>,' $R/e20r-pass2/raw.jsonl | less -S
```

A real address: purge as above. Amendment 3 doesn't apply.

**4.** A false fire: write what was checked in a private note, with no flagged text. Record the review. It binds to the legacy report:

`[server]`

```bash
node bench/front-door/pilot-report.mjs --privacy $R/e20r-pass2 --false-fire ~/study/false-fire-note.txt --reviewer <who>
```

**5.** Prune the stopped pass, and check it prints `"verified":true`:

`[server]`

```bash
node bench/front-door/validation-sample.mjs prune $R/e20r-pass2
```

**6.** Pilot round 2 is required, because the code changed. Run the two-round block above from "Its sites go on the dropped list", with an explanation in round 1's folder only if round 1 failed. The runner skips the stopped pass's sites itself.

**7.** Pass 3. It takes the dropped list of both rounds, and skips the 188 sites itself. It runs once:

`[server]`

```bash
node bench/front-door/replicate.mjs --pass 3 --pilot-dropped ~/study/pilot-sites-all.txt $COMMON
```

**8.** Set the run folder for every command in sections 4 and Failure recovery:

`[server]`

```bash
export RUN=$R/e20r-pass3
```

## 3. Pass 2

`[server]`

```bash
node bench/front-door/replicate.mjs --pass 2 --pilot-dropped ~/study/pilot-sites-all.txt $COMMON
```

To stop it between sites, for a complaint or anything else that can't wait:

`[server]`

```bash
touch ~/.penthera-e20r2-stop
```

## 4. After a whole pass

`RUN` is the run you are working on: `$R/e20r-pass3` under Amendment 3, as set above. Every command from here down uses it.

The order matters: the privacy report reads text the draw deletes.

`[server]`

```bash
node bench/front-door/pilot-report.mjs --privacy $RUN
```

`[server]`

```bash
node bench/front-door/validation-sample.mjs draw $RUN
```

`draw` prints `sampled` and `withheldFromDraw`, and writes `audit-frame.json`. Withheld records keep their label and grade, and stay out of the audit's frame. The headline audit is not estimable if any stratum is over 2.0% withheld: `headline` says so, and the report prints it above the claims. Nothing follows from that but the report: no further pass, draw or labels.

## 5. Server to laptop, without the key

`[server]` Don't pull or deploy from here until `score.json` exists: the score must run from the commit the run used.

The analysis needs the pass 1 and E20 raw files, which stay on the laptop, so the server can't run it. The key stays on the server until both label files exist.

`[laptop]` A clean, detached checkout of the run's commit, used for the analysis and the report. Take the commit from `gitAtStart.commit` in `manifest.json`. Nothing else may be open in it:

```bash
git clone --no-hardlinks <repository> ~/study/e20r-checkout && git -C ~/study/e20r-checkout checkout --detach <run commit>
```

`[laptop]` From that checkout. The run's Node version is required, and the laptop's own Node is newer. Set `NODE22` to a Node v22.23.4 binary. On an arm64 Mac, the npm package `node-bin-darwin-arm64@22.23.4` holds one. Don't use `npx -y node@22.23.4` for this: on a Mac it can run the laptop's own Node, with no error.

```bash
export NODE22=<path to a Node v22.23.4 binary>
```

`[laptop]` This stops on any other version, which must also be the version in `manifest.json`, and only then installs:

```bash
test "$("$NODE22" -v)" = v22.23.4 && npm ci
```

`[laptop]` The same run, named as on the server:

```bash
export RUN=bench/front-door/results/e20r-pass3
```

`[laptop]` Pull the run folder without the key. It still holds the sample's text, so it never goes into a chat:

```bash
rsync -a --exclude validation-key.json <server>:penthera/$RUN/ <private run folder>/
```

`[laptop]` Check that this prints `rawSha256After` from `prune-manifest.json`:

```bash
shasum -a 256 <private run folder>/raw.jsonl
```

## 6. The analysis

`[laptop]` From the detached checkout. `--pass1` takes the deciding run, as the file's header says. The other inputs are private, and match their frozen hashes. It refuses a checkout or a Node version that isn't the run's:

```bash
"$NODE22" bench/front-door/analyze-r.mjs --pass1 <private run folder>/raw.jsonl --pass2 <pass 1 raw.jsonl> --e20 <E20 tranco raw.jsonl> <E20 yc raw.jsonl> --industries <industries.csv> --e20-excluded <e20-health-excluded.txt> --out <private run folder>/analysis.json
```

Read coverage, skips, `textWithheld` and bounds first, then the primary endpoints, then C1 to C11 in order. Nothing is re-cut after looking.

## 7. Labels and the score

The human and the model each label from the sheet, and neither sees the other's labels. The model labels first, and its file's hash is noted.

`[laptop]` Build the kit. `<sampled>` is the count `draw` printed. The kit shows the sheet's hash, and each labeler sends it back with their labels:

```bash
"$NODE22" bench/front-door/make-labeler-kit.mjs <private run folder>/validation-sheet.json ~/study/kit --expect <the sampled count draw printed>
```

`[laptop]` Send the kit to the labeler and the model. No other copy of the sheet is made. Write down every copy's path in the deletion ledger, `~/study/copies.txt`, so each can be deleted. Each labeler returns a file of `id,label` rows.

`[laptop]` Send both label files to the server, into the run folder:

```bash
scp human.csv <server>:penthera/$RUN/labels-human.csv
```

`[laptop]`

```bash
scp model.csv <server>:penthera/$RUN/labels-model.csv
```

`[server]` Bind each file to this draw's sheet, with the hash its labeler sent back. A manifest is written once, with no name in it:

```bash
node bench/front-door/validation-sample.mjs bind $RUN human <sheet hash>
```

`[server]`

```bash
node bench/front-door/validation-sample.mjs bind $RUN model <sheet hash>
```

`[server]` Score. It refuses anything that doesn't chain to this run's manifest, raw file, frame, sheet and key, and any study state that isn't the run's. It writes `$RUN/score.json` once. The metrics cover non-withheld records, with `worstCase` bounds beside them. A label with a frame under 20 holds nulls and says `under 20 in frame`:

```bash
node bench/front-door/validation-sample.mjs score $RUN
```

`[laptop]` Pull the key, the labels, their manifests and the score:

```bash
rsync -a <server>:penthera/$RUN/validation-key.json <server>:penthera/$RUN/score.json <server>:penthera/$RUN/labels-human.csv <server>:penthera/$RUN/labels-human.manifest.json <server>:penthera/$RUN/labels-model.csv <server>:penthera/$RUN/labels-model.manifest.json <private run folder>/
```

`[laptop]` Assemble the one report that joins the claims and the audit. It proves the chain from the raw file, runs the score and the whole analysis again, compares every field, and writes nothing on any difference. It takes as long as the analysis:

```bash
"$NODE22" bench/front-door/report-tables.mjs --run <private run folder> --analysis <private run folder>/analysis.json --score <private run folder>/score.json --out <private run folder>/final-report.md --pass2 <pass 1 raw.jsonl> --e20 <E20 tranco raw.jsonl> <E20 yc raw.jsonl> --industries <industries.csv> --e20-excluded <e20-health-excluded.txt>
```

`[laptop]` Dated notes go on `main` only after `final-report.md` exists. They can't reach the detached checkout.

## 8. Deletions and the server's end

- `[labeler]` Deletes every copy of the sheet and says so. `[laptop]` The date goes in the ledger, and every path in `~/study/copies.txt` is checked gone, the kit included.
- `[server]` The server goes after the pull is checked and the score is done, on the maintainer's go.
- `[laptop]` The private evidence goes 12 months after publication, from every copy.

## Failure recovery

`textWithheld` isn't a failure. A record whose page or error text fired the detector is written without any of that text, and the run goes on. Pass 3 never stops for this. A pilot round fails its seal past 2 of 50.

Every failed run ends in a prune or a purge. A prune reads the file back and prints `"verified":true`. If it doesn't, the run isn't closed.

| What happened | Exit | Do this |
|---|---|---|
| Usage error | 2 | Fix the command. Nothing ran. |
| Refused by the gate | 3 | Read the reason. Nothing ran. |
| Something changed during the run | 4 | Do what the runner printed. Pilot: seal, then prune. A pass: prune. The run decides nothing. |
| Stopped: resolver failures, stop file, source address, signal | 5 | Do what the runner printed. Pilot: seal, then prune. A pass: prune, and report what ran as partial. |
| Hard kill, crash or full disk | none | Prune only. The run counts as interrupted. |
| Prune refuses, or the privacy report isn't clean | 3 or 1 | Stop. A person reviews the flagged fields first (below). |

`[server]`

```bash
node bench/front-door/validation-sample.mjs prune $RUN
```

### A privacy miss

This holds for a pilot round and for pass 3. For a pilot round, `export RUN=$R/e20r-pilot-<k>` first. A false fire must not cost the run, so nobody purges yet. If there is no privacy report yet, write it:

`[server]`

```bash
node bench/front-door/pilot-report.mjs --privacy $RUN
```

1. A person reads `flaggedFields` in `$RUN/privacy-report.json`. It names fields and counts, never text.
2. That person opens the flagged records on the server only. Nothing goes to a chat, a ticket, a shared log, the terminal scrollback of a shared session, or a hosted model.
3. A confirmed false fire: write what was checked in a private note, with no flagged text in it, then record it. The analysis reports it as a deviation.

`[server]`

```bash
node bench/front-door/pilot-report.mjs --privacy $RUN --false-fire ~/study/false-fire-note.txt --reviewer <who>
```

4. A real miss: purge, with the `purgeConfirm` code the report printed. Report a pass 2 as partial. A pilot round needs a seal first if it has a finished manifest, and pass 2 refuses it without a verified purge or a recorded false fire.

`[server]`

```bash
node bench/front-door/validation-sample.mjs purge $RUN --confirm <purgeConfirm>
```

- `purge` refuses without that code, the first 12 characters of the raw file's hash. The report's code holds until the file changes. After a prune, or for a crashed run with no report, take it from the file:

`[server]`

```bash
sha256sum $RUN/raw.jsonl | cut -c1-12
```

- `purge` deletes the whole per-site raw file and writes `purge-manifest.json` with the original hash and the disposition. It works on finished, partial, crashed and privacy-failed runs, and it can't be undone. The run can't be analyzed afterward. There is no field-level cleaning.
- A pruned or purged round's sites stay on the dropped list, and `pilot-sites.txt` stays in its folder.
- Pass 2 and pass 3 are never resumed or restarted. A new run needs a new registration.
- A complaint: `touch ~/.penthera-e20r2-stop`, prune, reply. Remove the stop file only once the reason is settled.
- A first SIGINT or SIGTERM ends the run after the visits in flight, up to 30 seconds. A second one kills it.
