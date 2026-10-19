/**
 * `penthera ui [--port 0] [--open] [--project <dir>]... [--reports <dir>] [--demo]`
 *
 * Starts the local dashboard on 127.0.0.1 and prints a one-time URL. See
 * docs/dashboard.md for the security model.
 */
import { parseArgs } from "node:util";
import { spawn } from "node:child_process";
import { bold, dim, red, green } from "./ansi.js";

const HELP = `
  ${bold("penthera ui")}: the local dashboard, on 127.0.0.1 only

  ${dim("Usage")}
    $ penthera ui [--open] [--port <n>] [--project <dir>]... [--reports <dir>]
    $ penthera ui --demo          Realistic fake data, for a first look or screenshots

  ${dim("Options")}
        --port <n>          Port to listen on (default: 0, a random free port)
        --open              Open the one-time URL in your browser
        --project <dir>     Folder the dashboard may read and run the agent loop in
                            (repeatable; default: the current folder)
        --reports <dir>     Report JSON folder (default: <first project>/reports)
        --demo              Seed fake data; nothing is read from disk
    -h, --help              Show this help

  The URL holds a one-time token. Opening it sets a session cookie; the token
  then stops working. Nothing outside the project folders and ~/.penthera is
  read, and the server never contacts the network. Ctrl-C stops it.
`;

function openBrowser(url) {
  const [cmd, args] = process.platform === "darwin" ? ["open", [url]]
    : process.platform === "win32" ? ["cmd", ["/c", "start", "", url]]
      : ["xdg-open", [url]];
  try {
    spawn(cmd, args, { stdio: "ignore", detached: true }).unref();
  } catch { /* the URL is printed anyway */ }
}

export async function runUi(argv, { version }) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: false,
      options: {
        port: { type: "string", default: "0" },
        open: { type: "boolean", default: false },
        project: { type: "string", multiple: true },
        reports: { type: "string" },
        demo: { type: "boolean", default: false },
        help: { type: "boolean", short: "h", default: false },
      },
    });
  } catch (e) {
    process.stderr.write(`  ${red("Error")} ${e.message}\n${HELP}`);
    return 2;
  }
  const opts = parsed.values;
  if (opts.help) { console.log(HELP); return 0; }
  const port = Number(opts.port);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    process.stderr.write(`  ${red("Error")} --port must be 0-65535\n`);
    return 2;
  }

  const { startUiServer } = await import("../ui/server.js");
  let ui;
  try {
    ui = await startUiServer({ port, projects: opts.project, reportsDir: opts.reports, demo: opts.demo, version });
  } catch (e) {
    process.stderr.write(`  ${red("Not started")} ${e.message}\n`);
    return 2;
  }

  process.stdout.write(`\n  ${bold("penthera ui")}${opts.demo ? dim("  (demo data)") : ""}\n`);
  process.stdout.write(`  ${green(ui.url)}\n`);
  process.stdout.write(dim(`  one-time link: it signs this browser in once, then stops working\n`));
  process.stdout.write(dim(`  listening on 127.0.0.1:${ui.port} only. Ctrl-C to stop\n\n`));
  if (opts.open) openBrowser(ui.url);

  await new Promise((resolve) => {
    const stop = () => { process.stdout.write("\n  Stopped.\n"); ui.close().then(resolve); };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
  return 0;
}
