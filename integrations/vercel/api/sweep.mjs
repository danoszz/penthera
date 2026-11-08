// GET /sweep, called by the weekly cron in vercel.json. The route lives in lib/app.mjs.
import { route } from "../lib/instance.mjs";

export const config = { maxDuration: 60 };

export default route("sweep");
