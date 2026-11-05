section: Security
docs: none, report output only; no flag or format changes

- **A short secret is no longer shown in full in reports.** The mask kept the first and last 4 characters of the whole match, so an assignment with a short value showed the value itself: `DB_PASSWORD=Xk9q` became `DB_P…Xk9q`, in the JSON, Markdown and SARIF reports, the pre-commit hook and PR comments. Now an assignment keeps its name and masks only the value, a value under 20 characters shows as `***`, and a longer one shows its first and last 4, with a closing quote kept outside. If you shared a report from an earlier version, check it for short secrets and rotate any it shows.
