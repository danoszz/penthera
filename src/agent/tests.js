/**
 * Run the project's own test script during verification (--run-tests only).
 *
 * Uses `node --run test` rather than `npm test`: it runs the package.json script
 * directly, without npm's update check or registry lookups. The script itself is
 * the project's code, so the user opts in to running it with --run-tests.
 */
import { spawn } from "node:child_process";
import { readPackageJson } from "../../lib/fix/util.js";

const NPM_PLACEHOLDER = /no test specified/i;

/** True when package.json has a real `test` script. */
export function hasTestScript(repoPath) {
  const script = readPackageJson(repoPath)?.scripts?.test;
  return typeof script === "string" && script.trim() !== "" && !NPM_PLACEHOLDER.test(script);
}

/**
 * @param {string} repoPath
 * A test script can leave a server behind that holds the output pipes open, so
 * "close" may never fire. The script's own exit is the answer: after exitGrace
 * for the last output, or at the timeout, its process group goes and the run
 * ends whatever is still attached.
 *
 * @param {{ timeout?: number, exitGrace?: number, killGrace?: number, progressEvery?: number, onProgress?: (ms: number) => void }} [opts]
 * @returns {Promise<{ ok: boolean, exitCode: number|null, durationMs: number, output: string }>}
 */
export function runProjectTests(repoPath, { timeout = 10 * 60_000, exitGrace = 2_000, killGrace = 5_000, progressEvery = 30_000, onProgress = null } = {}) {
  const start = Date.now();
  return new Promise((resolve) => {
    const grouped = process.platform !== "win32";
    const child = spawn(process.execPath, ["--run", "test"], {
      cwd: repoPath,
      env: { ...process.env, CI: "1", NO_UPDATE_NOTIFIER: "1" },
      stdio: ["ignore", "pipe", "pipe"],
      detached: grouped,
    });
    let output = "";
    const keep = (chunk) => {
      output = (output + chunk).slice(-8_000); // the tail is enough to say why it failed
    };
    child.stdout.on("data", keep);
    child.stderr.on("data", keep);

    const signal = (name) => {
      try {
        if (grouped) process.kill(-child.pid, name);
        else child.kill(name);
      } catch { /* already gone */ }
    };
    // In its own group the script gets no Ctrl-C from the terminal, so pass it on.
    const onExit = () => signal("SIGKILL");
    const onSignal = (name) => {
      signal("SIGKILL");
      if (process.listenerCount(name) === 1) {
        process.off(name, onSignal);
        process.kill(process.pid, name);
      }
    };
    const STOP_SIGNALS = ["SIGINT", "SIGTERM", "SIGHUP"];
    process.on("exit", onExit);
    for (const name of STOP_SIGNALS) process.on(name, onSignal);
    const timers = [];
    const beat = onProgress ? setInterval(() => onProgress(Date.now() - start), progressEvery) : null;
    beat?.unref();
    const later = (fn, ms) => { const t = setTimeout(fn, ms); t.unref(); timers.push(t); };
    let done = false;
    const finish = (code, extra = "") => {
      if (done) return;
      done = true;
      for (const t of timers) clearTimeout(t);
      clearInterval(beat);
      process.off("exit", onExit);
      for (const name of STOP_SIGNALS) process.off(name, onSignal);
      signal("SIGKILL"); // whatever the script left behind
      child.stdout.destroy();
      child.stderr.destroy();
      resolve({ ok: code === 0, exitCode: code, durationMs: Date.now() - start, output: output + extra });
    };

    later(() => {
      signal("SIGTERM");
      later(() => finish(null, `\ntests timed out after ${timeout} ms and were stopped`), killGrace);
    }, timeout);
    child.on("error", (e) => {
      output = String(e.message);
      finish(null);
    });
    child.on("exit", (code) => later(() => finish(code), exitGrace));
    child.on("close", (code) => finish(code));
  });
}
