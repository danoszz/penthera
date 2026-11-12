section: Changed

- **The agent brief keeps to a budget of about 500 tokens.** It shows the 5
  worst groups to act on, the 3 worst to check first, one line of likely
  noise, 3 Not checked lines and 3 Next commands, in at most 2,000
  characters. The counts on the verdict line still cover every finding. When
  the budget leaves something out, a last line, **Not shown here**, counts it
  exactly and says where it is: the `brief` field of `--json`, the full
  report, or `structuredContent.brief` in an MCP result. Groups are ordered
  by severity, then confidence, then group size, so a cut keeps the worst,
  never the first by file order; MCP `findings` (and `max_findings`) now sort
  by severity, then confidence, to match. Long titles and paths are cut with
  an ellipsis inside their line, after the secret scrubber runs. The JSON
  brief and the terminal report keep everything. On this repo the brief went
  from 4,787 to 1,859 characters. Found by E9: one brief opened with 23 items
  to act on, and long, noisy briefs misled the agents that read them.
