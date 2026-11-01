section: Docs

- **The E11b split manifests left the repo.** They're assets of the v2.2.0 release now. `npm run bench:public -- --fetch-split` gets them and checks each against `bench/public/split.sha256`.
- The action examples pin the v2.2.0 commit, and the upgrade test in the install matrix starts from 2.2.0.
