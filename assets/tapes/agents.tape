# `penthera agents` on the malicious AI-tooling fixture.
# Run from the repo root: vhs assets/tapes/agents.tape
Output assets/demo-agents.gif
Require node
Source assets/tapes/_settings.tape

Hide
Type "export PENTHERA_NO_ONBOARDING=1 && alias penthera='node bin/penthera.js' && cd tests/fixtures/agents && clear" Enter
Sleep 500ms
Show

Type "penthera agents malicious" Sleep 400ms Enter
Sleep 7s
