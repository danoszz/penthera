// POST /webhook. The route lives in lib/app.mjs.
import { route } from "../lib/instance.mjs";

// Vercel waits 30 seconds for a 2xx.
export const config = { maxDuration: 25 };

export default route("webhook");
