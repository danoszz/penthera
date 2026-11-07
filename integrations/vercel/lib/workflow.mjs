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
export const WORKFLOW_SOURCE = "https://github.com/danoszz/penthera/blob/main/integrations/vercel/workflow/penthera-vercel.yml";

/**
 * The file GitHub's prefill link carries: the template without its full-line comments, because the
 * link has a size limit, and one line that says where the commented file is. The same workflow:
 * a test parses both and compares them. The copy box on the page keeps every comment.
 */
export const PREFILL_YAML = `# Penthera on Vercel. The file with its comments: ${WORKFLOW_SOURCE}\n${WORKFLOW_YAML.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n").replace(/\n{3,}/g, "\n\n").replace(/^\n+/, "")}`;

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

/**
 * How long, in seconds, Vercel waits for the relay before the run ends as `timeout`. The job's own
 * limit is 15 minutes; this leaves room for a queued runner. Vercel's default is 300.
 */
export const CHECK_TIMEOUT_SECONDS = 1200;

/**
 * The body of POST /v2/projects/{id}/checks for one project: a check this integration owns. Vercel
 * refuses `source.kind: "git-provider"` from an integration's token (400 not_implemented, 7 Nov),
 * so the workflow's result reaches the check through POST /report instead (README, "The relay").
 */
export function checkBody(configurationId, integrationId) {
  return {
    name: CHECK_LABEL,
    requires: "deployment-url",
    // Live Vercel answers "deployment-promotion" with 400 not_implemented (7 Nov 2026): only
    // "deployment-alias" and "none" work. "deployment-alias" holds the production domain on the
    // last good deployment until the check passes.
    blocks: "deployment-alias",
    targets: ["production"],
    isRerequestable: false,
    timeout: CHECK_TIMEOUT_SECONDS,
    source: { kind: "integration", ...(integrationId ? { integrationId } : {}), integrationConfigurationId: configurationId },
  };
}

/** True for the integration-owned check that this installation registered. */
export function isIntegrationCheck(check, configurationId) {
  return (
    check?.source?.kind === "integration" &&
    typeof configurationId === "string" &&
    configurationId.length > 0 &&
    check.source.integrationConfigurationId === configurationId
  );
}

/**
 * True for a check this integration made under any of its installations: Vercel's source names
 * our integration id. `integrationId` must be known; without it, nothing counts.
 */
export function isOurIntegrationsCheck(check, integrationId) {
  return check?.source?.kind === "integration" && typeof integrationId === "string" && /^oac_/.test(integrationId) && check.source.integrationId === integrationId;
}

/**
 * True for a check this integration registered on the project: the integration-owned check of this
 * installation, or the git-provider check that earlier server versions tried to register.
 */
export function isOurCheck(check, projectName, configurationId) {
  if (isIntegrationCheck(check, configurationId)) return true;
  return check?.source?.kind === "git-provider" && check?.source?.externalCheckName === checkName(projectName);
}

const SLUG = /^[A-Za-z0-9_.-]{1,100}$/;

/** GitHub's "new file" page with the path and the workflow filled in, or null for an odd repo name. */
export function githubNewFileUrl(repo, branch) {
  const [owner, name, extra] = String(repo ?? "").split("/");
  if (extra !== undefined || !SLUG.test(owner ?? "") || !SLUG.test(name ?? "")) return null;
  const ref = String(branch || "main").split("/").map(encodeURIComponent).join("/");
  const q = new URLSearchParams({ filename: WORKFLOW_PATH, value: PREFILL_YAML });
  return `https://github.com/${owner}/${name}/new/${ref}?${q}`;
}
