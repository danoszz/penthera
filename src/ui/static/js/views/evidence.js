import { h, put, panel, empty, clear, announce, fig } from "../dom.js";
import { ago, stamp, shortProject } from "../format.js";
import { SCREENS, EMPTY } from "../copy.js";

export async function render(root, { api, params }) {
  const [{ bundles }, o] = await Promise.all([api.get("/api/evidence"), api.get("/api/overview")]);
  put(root, h("h1", {}, SCREENS.evidence.title), h("p", { class: "lede" }, SCREENS.evidence.lede));

  const out = h("div");
  const keys = o.projects.map((p) => p.key);
  const projSel = h("select", { id: "ev-project", "aria-label": "Project" }, keys.map((k) => h("option", { value: k, selected: k === params.get("project") }, shortProject(k))));
  const create = h("button", { type: "button", class: "btn primary", disabled: !keys.length }, "Create evidence bundle ▸");
  const downloads = h("p", { class: "filters" });
  const createMsg = h("p", { class: "muted", "aria-live": "polite" });

  const paintDownloads = () => {
    const p = projSel.value;
    clear(downloads).append(
      h("span", { class: "muted" }, "Download the latest report as Markdown ::"),
      ...["auditor", "owner", "developer"].map((a) => h("a", { class: "btn", href: `/api/report?${new URLSearchParams({ project: p, audience: a })}`, download: "" }, `${a}.md`)),
    );
  };
  projSel.addEventListener("change", paintDownloads);
  if (keys.length) paintDownloads();

  create.addEventListener("click", async () => {
    create.disabled = true;
    createMsg.textContent = "Writing the bundle and hashing every file…";
    try {
      const r = await api.post("/api/evidence/create", { project: projSel.value });
      const v = await api.post("/api/evidence/verify", { id: r.id });
      createMsg.textContent = `Written to ${r.path} :: ${v.ok ? "verified" : "verification failed"}.`;
      announce(createMsg.textContent);
      await refresh();
      clear(out).append(report({ path: r.path }, v));
    } catch (e) {
      createMsg.textContent = e.message;
    } finally {
      create.disabled = false;
    }
  });

  const tableSlot = h("div");
  async function refresh() {
    const { bundles: list } = await api.get("/api/evidence");
    clear(tableSlot).append(bundleTable(list));
  }

  function bundleTable(list) {
    if (!list.length) return empty(EMPTY.evidence);
    const rows = list.map((b) => {
      const result = h("td", { class: "muted", "aria-live": "polite" }, "not checked");
      const btn = h("button", { type: "button", class: "btn" }, "Verify");
      btn.addEventListener("click", async () => {
        btn.disabled = true;
        result.textContent = "hashing…";
        result.className = "muted";
        try {
          const r = await api.post("/api/evidence/verify", { id: b.id });
          result.textContent = r.ok ? "[VERIFIED]" : `[FAILED] ${r.problems.length} problem${r.problems.length === 1 ? "" : "s"}`;
          result.className = r.ok ? "ok" : "bad";
          clear(out).append(report(b, r));
          announce(`${b.path}: ${r.ok ? "verified" : "verification failed"}`);
        } catch (e) {
          result.textContent = e.message;
          result.className = "bad";
        } finally {
          btn.disabled = false;
        }
      });
      return h("tr", {},
        h("td", { class: "t1" }, b.path),
        h("td", { class: "trunc hide-narrow", title: b.target || "" }, shortProject(b.target)),
        h("td", { class: "muted hide-narrow" }, ago(b.generatedAt)),
        h("td", { class: "num" }, String(b.artifacts)),
        h("td", {}, b.signed ? h("span", { class: "chip on" }, "signed") : h("span", { class: "chip" }, "unsigned")),
        h("td", {}, btn),
        result,
      );
    });
    return h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ...["Bundle", "Target", "Written", "Files", "Signature", "", "Result"].map((t, i) => h("th", { class: [i === 3 ? "num" : null, i === 1 || i === 2 ? "hide-narrow" : null] }, t)))),
      h("tbody", {}, rows),
    ));
  }
  put(tableSlot, bundleTable(bundles));

  put(root, h("div", { class: "grid" },
    panel("For your auditor", { class: "span-12" },
      keys.length ? h("div", {},
        h("p", { class: "t1" }, "One folder they can check without trusting you: the JSON, Markdown and SARIF reports, the auditor, owner and developer reports, and manifest.json with a SHA-256 for each file."),
        h("div", { class: "filters" }, h("label", { class: "field" }, h("span", {}, "Project"), projSel), create),
        createMsg,
        downloads,
        h("p", { class: "muted" }, "To sign it, write the bundle from the CLI with --evidence <dir> --sign-key ~/.ssh/id_ed25519. They verify with penthera evidence verify <dir>."),
      ) : empty("Scan a project first: a bundle is made from its latest report."),
    ),
    panel("Bundles in the reports folder", { class: "span-12" }, tableSlot, fig("fig 1 :: verify recomputes every hash and checks the SSH signature", `${bundles.length} bundles`)),
    h("div", { class: "span-12" }, out),
  ));
}

function report(b, r) {
  return panel(`Verification :: ${b.path}`, {},
    h("p", { class: r.ok ? "ok" : "bad" }, r.ok ? "[OK] Every file matches the manifest." : "[!] NOT VERIFIED"),
    h("ul", { class: "list" }, r.files.map((f) => h("li", {},
      h("span", { class: f.ok ? "ok" : "bad" }, f.ok ? "ok  " : "FAIL"),
      h("span", { class: "grow t1" }, f.path),
      f.ok ? null : h("span", { class: "bad" }, f.reason),
    ))),
    r.signature ? h("p", {}, h("span", { class: r.signature.ok ? (r.signature.status === "valid" ? "ok" : "t1") : "bad" }, `signature ${r.signature.status} :: `), r.signature.detail) : null,
    r.problems.length ? h("pre", { class: "block" }, r.problems.map((p) => `- ${p}`).join("\n")) : null,
    fig(`checked ${stamp(new Date().toISOString())}`, "sha-256"),
  );
}
