// The project's tabs besides Findings: Dependencies, AI tooling, History and
// Proof. These were the right-hand cards; they now live with the project they
// describe, so the inspector on the right only ever shows one thing.
import { h, empty, sevBadge, announce } from "./dom.js";
import { api } from "./api.js";
import { state, set } from "./state.js";
import { bars, SHADE, trendChart } from "./charts.js";
import { ago, keyParts, runBelongs, stamp, shortProject, plural, pct } from "./format.js";
import { EMPTY } from "./copy.js";

const section = (title, aside, ...body) => h("section", { class: "section" },
  h("h2", {}, h("span", {}, title), aside ? h("span", {}, aside) : null), ...body);
const label = (text) => h("p", { class: "label" }, text);
// Node.append() prints a null as the text "null", so sections that don't apply are dropped.
const put = (el, ...parts) => el.append(...parts.filter(Boolean));
const failed = (e) => h("p", { class: "bad", role: "alert" }, e.message);

// ── Dependencies ────────────────────────────────────────────────────────

const CAP_SEV = { "install-scripts": "high", obfuscated: "high", "ai-config-write": "critical", "ai-cli-invoke": "critical", "token-harvest": "critical" };

const forProject = (path, project) => (project ? `${path}?project=${encodeURIComponent(project)}` : path);

export async function depsTab(el, project = null) {
  let d;
  try { d = await api.get(forProject("/api/deps", project)); } catch (e) { el.append(failed(e)); return; }
  const l = d.latest;
  if (!l) { el.append(section("Dependencies", "", empty(EMPTY.deps))); return; }
  const diff = l.diff;
  const gained = diff ? diff.upgraded.reduce((n, u) => n + u.gained.length, 0) + diff.added.reduce((n, a) => n + a.capabilities.length, 0) : 0;
  const chip = (id, plus) => h("span", { class: `chip ${CAP_SEV[id] ? "inv" : ""}` }, `${plus ? "+" : ""}${id}`);
  put(el,
    section("Dependencies", `${l.ecosystem} · ${plural(l.total, "package")} · ${ago(l.ts)}`,
      h("dl", { class: "kv" },
        h("dt", {}, "packages"), h("dd", {}, `${l.total} (${l.direct} direct) · ${l.lockfile}`),
        h("dt", {}, "read"), h("dd", { class: l.scanned < l.total ? "bad" : null }, `${l.scanned} of ${l.total}`),
        h("dt", {}, "diff"), h("dd", {}, diff ? `+${diff.added.length} added · ~${diff.upgraded.length} upgraded · -${diff.removed.length} removed vs ${diff.base}` : "no base compared"),
        h("dt", {}, "gained"), h("dd", {}, plural(gained, "capability", "capabilities")),
        h("dt", {}, "typosquats"), h("dd", { class: l.typosquats.length ? "bad" : null }, l.typosquats.length ? l.typosquats.map((t) => `${t.name} ~ ${t.similarTo}`).join(", ") : "none"))),
    diff ? section("What changed", `vs ${diff.base}`,
      h("ul", { class: "mini" },
        diff.added.map((a) => h("li", { class: "stacked" }, h("span", {}, `+ ${a.name}@${a.version}`), h("span", { class: "chips" }, a.capabilities.map((c) => chip(c, true))))),
        diff.upgraded.filter((u) => u.gained.length).map((u) => h("li", { class: "stacked" }, h("span", {}, `${u.name} ${u.from} → ${u.to}`), h("span", { class: "chips" }, u.gained.map((c) => chip(c, true))))))) : null,
    section("Capabilities in the tree", "",
      !Object.values(l.capabilityCounts).some(Boolean) ? h("p", { class: "muted" }, l.scanned < l.total ? `None in the ${plural(l.scanned, "package")} read.` : "None found.") : bars(Object.entries(l.capabilityCounts).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]).map(([id, n]) => ({ label: id, value: n, ch: SHADE[CAP_SEV[id] || "low"] })), { width: 28 })),
    d.installs.length ? section("Install firewall", plural(d.installs.length, "decision"),
      h("ul", { class: "mini" }, d.installs.map((i) => {
        const deny = i.changes.some((c) => c.deny.length) || i.action === "refused";
        return h("li", {}, h("span", { class: "chip" }, deny ? "Refused" : i.clean ? "Clean" : "Approved"), h("span", { class: "grow" }, i.specs.join(" ")), h("span", { class: "muted" }, ago(i.ts)));
      }))) : null,
  );
}

// ── AI tooling ──────────────────────────────────────────────────────────

export async function aiTab(el, project = null) {
  let d;
  try { d = await api.get(forProject("/api/ai", project)); } catch (e) { el.append(failed(e)); return; }
  const l = d.latest;
  if (!l) { el.append(section("AI tooling", "", empty(EMPTY.ai))); return; }
  const lock = l.lock || {};
  const drift = (lock.changed || 0) + (lock.added || 0) + (lock.removed || 0);
  put(el,
    section("AI tooling", ago(l.ts),
      h("div", { class: "head" },
        h("span", { class: `grade lg grade-${l.grade || "x"}` }, l.grade || "–"),
        h("div", {}, h("div", { class: "t1" }, l.grade ? `score ${l.score}/100` : "nothing to assess"), h("div", { class: "muted" }, `grade history ${d.history.map((x) => x.grade || "–").join(" → ")}`))),
      h("dl", { class: "kv" },
        h("dt", {}, "penthera.lock"), h("dd", { class: drift ? "bad" : null }, lock.status === "missing" ? "not pinned" : drift ? `${lock.changed || 0} changed · ${lock.added || 0} new · ${lock.removed || 0} removed` : "no drift"),
        h("dt", {}, "inventory"), h("dd", {}, [plural(l.inventory.skills || 0, "skill"), plural(l.inventory.mcpServers || 0, "MCP server"), plural(l.inventory.hooks || 0, "hook")].join(" · ")),
        h("dt", {}, "hidden content"), h("dd", { class: l.hidden.length ? "bad" : null }, l.hidden.length ? plural(l.hidden.length, "hit") : "none"))),
    l.hidden.length ? section("Hidden content", plural(l.hidden.length, "hit"),
      h("ul", { class: "rows" }, l.hidden.map((x) => h("li", {}, h("div", { class: "row static" }, sevBadge(x.severity), h("span", { class: "t" }, x.title), h("span", { class: "tag" }, ""), x.location ? h("span", { class: "where" }, x.location) : null))))) : null,
    l.findings.length ? section("Findings", plural(l.findings.length, "finding"),
      h("ul", { class: "rows" }, l.findings.map((x) => h("li", {}, h("div", { class: "row static" }, sevBadge(x.severity), h("span", { class: "t" }, x.title))))) ) : null,
  );
}

// ── History: trend, runs, commits, memory ───────────────────────────────

export async function historyTab(el, project) {
  const p = project ? state.overview?.projects?.find((x) => x.key === project) : null;
  const points = p ? p.trend.map((t) => ({ ts: t.ts, total: t.total, severe: (t.critical || 0) + (t.high || 0) })) : [];
  if (points.length) el.append(section("Open findings per scan", plural(points.length, "scan"), trendChart(points, { width: 640, height: 160 })));

  const runs = [
    ...state.runs.live.filter((r) => runBelongs(project, r.repo, r.url)).map((r) => ({ live: true, kind: r.kind, at: r.startedAt, status: r.status, run: r })),
    ...state.runs.past.filter((l) => runBelongs(project, l.target.repo, l.target.url)).map((l) => ({ live: false, kind: "loop", at: l.startedAt, past: l })),
  ];
  el.append(section("Runs", plural(runs.length, "run"),
    runs.length ? h("ul", { class: "rows" }, runs.map((r) => h("li", {}, h("button", {
      type: "button", class: "row",
      onclick: () => set(r.live ? { sel: { kind: "run", key: r.run.id, run: r.run } } : { sel: { kind: "past", key: r.at, past: r.past } }),
    },
    h("span", { class: "tag" }, r.live ? r.status : stamp(r.at).slice(5)),
    h("span", { class: "t" }, `${({ scan: "Scan", deps: "Dependency check", agents: "AI tooling audit", loop: "Fix loop" })[r.kind] || r.kind}${project ? "" : ` · ${shortProject(r.run?.repo || r.past?.target?.repo)}`}`),
    h("span", { class: "tag" }, ago(r.at)),
    r.past ? h("span", { class: "where" }, `${r.past.totals.verified} verified · ${r.past.totals.failed} failed · findings ${r.past.findings.initial ?? "?"} → ${r.past.findings.final ?? "?"} · ${r.past.branch}`) : null)))) : empty(EMPTY.history)));

  const past = state.runs.past.filter((l) => runBelongs(project, l.target.repo, l.target.url));
  const fixes = past.flatMap((l) => l.iterations.flatMap((it) => it.fixes.filter((f) => f.commit).map((f) => ({ ...f, branch: l.branch }))));
  let env = { fixBranches: [] };
  try { env = await api.get(`/api/env?project=${encodeURIComponent(project || "")}`); } catch { /* shown as none */ }
  el.append(section("Commits the fix loop made", plural(fixes.length, "fix", "fixes"),
    fixes.length ? h("ul", { class: "mini" }, fixes.map((f) => h("li", {},
      h("span", {}, "✓"), h("span", { class: "grow" }, f.title, h("span", { class: "muted" }, ` · ${f.branch}`)),
      h("code", { class: "muted", title: `git show ${f.commit}` }, f.commit.slice(0, 7))))) : empty(EMPTY.changes),
    env.fixBranches.length ? h("div", {}, label("Local fix branches"), h("ul", { class: "mini" }, env.fixBranches.map((b) => h("li", {}, h("code", { class: "grow" }, b))))) : null,
    h("p", { class: "muted prose" }, "Nothing is pushed. Review with git log --stat main..<branch>, then merge or push it yourself.")));

  let mem = { projects: [] };
  try { mem = await api.get("/api/memory"); } catch { /* shown as empty */ }
  const mine = mem.projects.filter((m) => project && (m.label === project || m.label.startsWith(`${project} `)));
  const list = mine.length ? mine : mem.projects;
  if (!list.length) { el.append(section("Memory", "", empty(EMPTY.memory))); return; }
  const recipes = new Map();
  for (const m of list) for (const r of m.recipes) {
    const c = recipes.get(r.recipe) || { verified: 0, failed: 0 };
    c.verified += r.verified;
    c.failed += r.failed;
    recipes.set(r.recipe, c);
  }
  const broken = list.filter((m) => m.chain !== "ok");
  const ttf = list.map((m) => m.medianTimeToFixDays).filter((x) => x != null);
  el.append(section("Memory", broken.length ? `${broken.length} broken` : "chain ok",
    h("dl", { class: "kv" },
      h("dt", {}, "chain"), h("dd", { class: broken.length ? "bad" : null }, broken.length ? `[!] broken in ${plural(broken.length, "project")} :: ignored there` : "✓ sha-256 hash chain"),
      h("dt", {}, "events"), h("dd", {}, String(list.reduce((n, m) => n + m.events, 0))),
      h("dt", {}, "fixes"), h("dd", {}, `${list.reduce((n, m) => n + m.verifiedFixes, 0)} verified · ${list.reduce((n, m) => n + m.failedFixes, 0)} failed`),
      h("dt", {}, "time to fix"), h("dd", {}, ttf.length ? `median ${Math.min(...ttf) === Math.max(...ttf) ? ttf[0] : `${Math.min(...ttf)}-${Math.max(...ttf)}`} days` : "-")),
    label("Recipe success"),
    bars([...recipes].map(([recipe, r]) => ({ label: `${recipe} ${pct(r.verified / Math.max(1, r.verified + r.failed))}`, value: r.verified })), { width: 24 })));
}

// ── Proof: what was touched, and evidence an auditor can check ──────────

export async function proofTab(el, project) {
  const target = project || state.overview?.projects?.[0]?.key || "";
  let env; let ev;
  try {
    [env, ev] = await Promise.all([api.get(`/api/env?project=${encodeURIComponent(target)}`), api.get("/api/evidence")]);
  } catch (e) { el.append(failed(e)); return; }
  const scanned = state.overview?.projects?.some((p) => p.key === target);

  el.append(section("What the last scan touched", shortProject(target),
    h("dl", { class: "kv" },
      h("dt", {}, "folder"), h("dd", {}, env.folder || keyParts(target).folder || "a URL target"),
      h("dt", {}, "branch"), h("dd", {}, env.branch ? `${env.branch}${env.head ? ` @ ${env.head}` : ""}` : "-"),
      h("dt", {}, "dashboard"), h("dd", {}, `${location.host}, no network`)),
    env.hosts.length ? h("ul", { class: "mini" },
      env.hosts.map((x) => h("li", {}, h("span", { class: "chip" }, x.thirdParty ? "3rd party" : "target"), h("span", { class: "grow" }, x.host), h("span", { class: "muted" }, plural(x.requests, "request")))),
      env.blocked.map((x) => h("li", {}, h("span", { class: "chip inv" }, "blocked"), h("span", { class: "grow" }, x.host), h("span", { class: "muted" }, "offline mode")))) : empty("No hosts recorded for the last scan."),
  ));

  const msg = h("p", { class: "muted prose", "aria-live": "polite" });
  const out = h("div");
  const create = h("button", { type: "button", class: "btn primary", disabled: !scanned }, "Create bundle");
  create.addEventListener("click", async () => {
    create.disabled = true;
    msg.textContent = "Writing the bundle and hashing every file…";
    try {
      const r = await api.post("/api/evidence/create", { project: target });
      const v = await api.post("/api/evidence/verify", { id: r.id });
      msg.textContent = `${r.path} :: ${v.ok ? "verified" : "verification failed"}`;
      announce(msg.textContent);
      set({ tab: "proof" });
    } catch (e) { msg.textContent = e.message; create.disabled = false; }
  });
  el.append(section("Evidence bundle", plural(ev.bundles.length, "bundle"),
    h("p", { class: "prose" }, "A bundle holds the latest scan, its inputs and a hash of every file, so an auditor can check nothing changed after the fact."),
    h("div", { class: "actions start" }, create,
      // A download through the API carries the session header; a plain link could not.
      ...["auditor", "owner", "developer"].map((a) => h("button", {
        type: "button", class: "btn", disabled: !scanned,
        onclick: () => api.download(`/api/report?${new URLSearchParams({ project: target, audience: a })}`).catch((e) => { msg.textContent = e.message; }),
      }, `${a} report`))),
    msg,
    ev.bundles.length ? h("ul", { class: "mini" }, ev.bundles.map((b) => {
      const res = h("span", { class: "muted" }, b.signed ? "signed" : "unsigned");
      const btn = h("button", { type: "button", class: "btn small" }, "Verify");
      btn.addEventListener("click", async () => {
        btn.disabled = true;
        res.textContent = "hashing…";
        const r = await api.post("/api/evidence/verify", { id: b.id }).catch((e) => ({ ok: false, problems: [e.message], files: [] }));
        res.textContent = r.ok ? "✓ intact" : `[!] ${plural(r.problems.length, "problem")}`;
        res.className = r.ok ? "t1" : "bad";
        out.replaceChildren(...(r.ok ? [] : [h("pre", { class: "block" }, r.problems.map((p) => `- ${p}`).join("\n"))]));
        btn.disabled = false;
      });
      return h("li", {}, h("span", { class: "grow", title: b.target || "" }, `${b.path} · ${ago(b.generatedAt)}`), res, btn);
    })) : empty(EMPTY.evidence),
    out));
}
