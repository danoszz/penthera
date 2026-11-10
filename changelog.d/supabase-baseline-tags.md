section: Fixed

- **A new or swapped Supabase key counts as new against a baseline.** Supabase
  service-role key findings now carry the same salted value tags as other
  secrets, so `--baseline -q` reports a key added to or replaced in a file the
  baseline already lists. Re-create older baselines to compare by value.
