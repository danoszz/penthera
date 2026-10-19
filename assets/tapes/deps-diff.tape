# `penthera deps --diff` between two generated lockfile trees
# (tests/fixtures/deps/build.js writes them; nothing suspicious is stored in git).
# Run from the repo root: vhs assets/tapes/deps-diff.tape
Output assets/demo-deps-diff.gif
Require node
Source assets/tapes/_settings.tape

Hide
Type "export PENTHERA_NO_ONBOARDING=1 && alias penthera='node bin/penthera.js'" Enter
Type "rm -rf /tmp/penthera-demo && node tests/fixtures/deps/build.js /tmp/penthera-demo >/dev/null && cd /tmp/penthera-demo && clear" Enter
Sleep 1s
Show

Type "penthera deps head --diff base" Sleep 400ms Enter
Sleep 8s
