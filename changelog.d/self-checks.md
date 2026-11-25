section: Security
docs: none, two checks on Penthera's own code and a contributor note; no flag, output or rule changes

- **Two new checks guard every change to a rule.** A timing check feeds each
  scanner input built from its own rule words and fails when the work grows
  faster than the input. A findings gate scans a corpus of vulnerable samples
  with the base branch's scanner and with the change, and fails when a finding
  goes missing or drops in severity, also when a harmless line named like a
  check is added. Both come from the 38 findings the Vercel Security Review
  logged against Penthera by 22 Nov: 20 were slowdowns and 14 were a real
  finding hidden or lowered.
