/**
 * The workflow file the user commits, and the Vercel check that waits for it.
 *
 * workflow/penthera-vercel.yml is a copy of docs/examples/vercel-deployment-check.yml
 * (roadmap row 125); a test keeps the two equal. It is a constant of this
 * server release: changing a pin in it means a new deploy, and the server
 * never serves rules or templates to the runner.
 */
import { readFileSync } from "node:fs";

export const WORKFLOW_PATH = ".github/workflows/penthera-vercel.yml";
export const WORKFLOW_YAML = readFileSync(new URL("../workflow/penthera-vercel.yml", import.meta.url), "utf8");

const WORKFLOW_NAME = /^name:\s*(.+?)\s*$/m.exec(WORKFLOW_YAML)?.[1] ?? "Penthera on Vercel";
const JOB_ID = "scan";
/** What Vercel shows on the deployment page. */
export const CHECK_LABEL = "Penthera";

/**
 * The commit status name the workflow reports, which the Vercel check must match
 * exactly. It is the status action's default: "<workflow> | <job> (<project> - <environment>)".
 */
export function checkName(projectName) {
  return `${WORKFLOW_NAME} | ${JOB_ID} (${projectName} - production)`;
}

/** The body of POST /v2/projects/{id}/checks for one project. */
export function checkBody(projectName) {
  return {
    name: CHECK_LABEL,
    requires: "deployment-url",
    blocks: "deployment-promotion",
    targets: ["production"],
    isRerequestable: false,
    source: { kind: "git-provider", provider: "github", externalCheckName: checkName(projectName) },
  };
}

/** True for a check this integration registered on the project. */
export function isOurCheck(check, projectName) {
  return check?.source?.kind === "git-provider" && check?.source?.externalCheckName === checkName(projectName);
}

const SLUG = /^[A-Za-z0-9_.-]{1,100}$/;

/** GitHub's "new file" page with the path and the workflow filled in, or null for an odd repo name. */
export function githubNewFileUrl(repo, branch) {
  const [owner, name, extra] = String(repo ?? "").split("/");
  if (extra !== undefined || !SLUG.test(owner ?? "") || !SLUG.test(name ?? "")) return null;
  const ref = String(branch || "main").split("/").map(encodeURIComponent).join("/");
  const q = new URLSearchParams({ filename: WORKFLOW_PATH, value: WORKFLOW_YAML });
  return `https://github.com/${owner}/${name}/new/${ref}?${q}`;
}
