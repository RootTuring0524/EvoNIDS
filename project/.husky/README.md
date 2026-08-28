# Git hook reservation

This directory intentionally contains no active hook. CI and local scripts expose
`lint`, `typecheck`, `test`, `lint:staged`, and `commitlint`; a repository owner can
bind those commands to Husky without changing the project structure.
