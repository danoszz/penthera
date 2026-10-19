# URL scan of the local mock server (tests/fixtures/mock-server.js).
# Run from the repo root: vhs assets/tapes/scan.tape
Output assets/demo-scan.gif
Require node
Source assets/tapes/_settings.tape

Hide
Type "export PENTHERA_NO_ONBOARDING=1 && alias penthera='node bin/penthera.js'" Enter
Type "MOCK_PORT=8765 node tests/fixtures/mock-server.js >/dev/null 2>&1 & sleep 1 && clear" Enter
Sleep 1.5s
Show

Type "penthera http://127.0.0.1:8765" Sleep 400ms Enter
Sleep 6s
Hide
Type "kill %1" Enter
