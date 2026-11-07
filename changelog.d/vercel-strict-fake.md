section: Changed
docs: none, the integration server only: tests, a local script and its logs; its README and privacy notice cover them, and nothing in the CLI, MCP tools, rules or Action changed

- **The Vercel integration's tests hold every request to what Vercel accepts.**
  Twice a value passed Vercel's published spec and was refused live. Each field
  the integration sends now has its allowed values and their source, from
  Vercel's docs, its spec and what live Vercel refused, and the test fake refuses
  anything else the way Vercel does. A new test walks the whole journey from the
  listing page to uninstall, and a local script runs the real server against the
  same fakes, so the pages can be clicked through by hand.
- **The Vercel integration's runtime logs show the good events too, and no
  ids.** An install, a check turned on or off, a result passed on and an
  uninstall each log an event name with at most a count or pass/fail. Error
  lines no longer carry the installation id, and any id in Vercel's error text
  is replaced, as the privacy notice promises: an error code and Vercel's
  error text at most.
