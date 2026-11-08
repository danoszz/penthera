// POST /report: the workflow's pass or fail, with a GitHub OIDC token. The route lives in lib/app.mjs.
import { route } from "../lib/instance.mjs";

export const config = { maxDuration: 25 };

export default route("report");
