section: Fixed
docs: none, only how git checks out this repository; nothing changes for npm users

- **A Windows clone with the default `core.autocrlf=true` runs again.** Git turned the bundled rule packs into CRLF on checkout, so their SHA-256 sums and signature no longer matched and every command stopped with "Bundled rule pack core failed verification". `.gitattributes` now keeps `lib/rules/` and the rule-pack test fixtures byte for byte. In an existing clone, delete `lib/rules` and `tests/fixtures/rules` and run `git checkout -- lib/rules tests/fixtures/rules`. The npm package was not affected.
