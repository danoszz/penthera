import { h, put, panel, empty, announce } from "../dom.js";
import { SCREENS } from "../copy.js";

export async function render(root, { api, meta, refreshMeta, theme }) {
  const [settings, mem] = await Promise.all([api.get("/api/settings"), api.get("/api/memory")]);

  const sw = h("button", { type: "button", class: "switch", role: "switch", "aria-checked": String(settings.offline), "aria-describedby": "egress-help" },
    h("span", {}, "Offline mode"), h("span", { class: "state" }, settings.offline ? "[ON]" : "[OFF]"));
  const help = h("p", { id: "egress-help", class: "muted" });
  const paint = (offline) => {
    sw.setAttribute("aria-checked", String(offline));
    sw.lastChild.textContent = offline ? "[ON]" : "[OFF]";
    help.textContent = offline
      ? "Scans started here contact only their target. No recon sources, no Retire.js download (the vendored snapshot is used)."
      : "Scans started here may also contact recon sources (certificate logs, web archives) and download the latest Retire.js database.";
  };
  paint(settings.offline);
  sw.addEventListener("click", async () => {
    try {
      const s = await api.post("/api/settings", { offline: sw.getAttribute("aria-checked") !== "true" });
      paint(s.offline);
      announce(`Offline ${s.offline ? "on" : "off"}`);
      await refreshMeta?.();
    } catch (e) {
      help.textContent = e.message;
    }
  });

  put(root, 
    h("h1", {}, "Settings"),
    h("p", { class: "lede" }, "For this dashboard session. Nothing here is written to disk."),
    h("div", { class: "grid" },
      panel("Egress", { class: "span-6" }, sw, help,
        h("p", { class: "panel-note" }, "The agent loop is always offline and limited to its URL host, whatever this says. The dashboard itself never contacts the network.")),
      panel("Where data comes from", { class: "span-6" },
        h("dl", { class: "kv" },
          h("dt", {}, "reports"), h("dd", {}, meta.reportsDir),
          h("dt", {}, "memory"), h("dd", {}, meta.memoryRoot),
          h("dt", {}, "projects"), h("dd", {}, meta.projects.map((p) => h("div", {}, p))),
        ),
        h("p", { class: "panel-note" }, "Only these folders and ~/.penthera are read. Move memory with PENTHERA_HOME; add folders with penthera ui --project <dir> --reports <dir>."),
      ),
      panel("Memory chains", { class: "span-12" },
        mem.projects.length ? h("div", { class: "table-wrap" }, h("table", {},
          h("thead", {}, h("tr", {}, ...["Project", "Chain", "Events", "Scans", "Suppressions", "Median time to fix"].map((t, i) => h("th", { class: i >= 2 ? "num" : null }, t)))),
          h("tbody", {}, mem.projects.map((p) => h("tr", {},
            h("td", { class: "trunc", title: p.label }, p.label),
            h("td", { class: p.chain === "ok" ? "ok" : "bad" }, p.chain === "ok" ? "[OK]" : `[BROKEN @ line ${p.brokenAt}]`),
            h("td", { class: "num" }, String(p.events)),
            h("td", { class: "num" }, String(p.scans)),
            h("td", { class: "num" }, String(p.suppressions)),
            h("td", { class: "num" }, p.medianTimeToFixDays == null ? "-" : `${p.medianTimeToFixDays}d`),
          ))),
        )) : empty("No memory yet."),
      ),
      panel("Session security", { class: "span-12" },
        h("dl", { class: "kv" },
          h("dt", {}, "bound to"), h("dd", {}, `${location.host} (127.0.0.1 only)`),
          h("dt", {}, "session"), h("dd", {}, "one-time URL token swapped for an HttpOnly, SameSite=Strict cookie"),
          h("dt", {}, "requests"), h("dd", {}, "Host header must be 127.0.0.1 or localhost (DNS rebinding); state changes need this page's Origin"),
          h("dt", {}, "page"), h("dd", {}, "strict CSP, no inline script, no framing, no CORS, no third-party anything"),
          h("dt", {}, "data"), h("dd", {}, meta.demo ? "--demo: fake data, nothing read from disk" : "local reports and memory"),
        ),
      ),
    ),
  );
}
