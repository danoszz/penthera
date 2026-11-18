# `penthera agents` on the malicious AI-tooling fixture.
# Run from the repo root: vhs assets/tapes/agents.tape
Output assets/demo-agents.gif
Require node
Source assets/tapes/_settings.tape

Hide
Type `export PENTHERA_NO_ONBOARDING=1 && alias penthera="node $PWD/bin/penthera.js" && DEMO="$(mktemp -d)" && node tests/fixtures/agents/malicious.js "$DEMO/malicious" >/dev/null && cd "$DEMO" && clear` Enter
Sleep 500ms
Show

Type "penthera agents malicious" Sleep 400ms Enter
Sleep 7s

# Remove the private demo folder.
Hide
Type `cd / && rm -rf "$DEMO"` Enter
