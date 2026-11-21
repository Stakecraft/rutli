# Changelog fragments

Each pull request adds **one small file** here instead of editing `CHANGELOG.md`, so merges stop
conflicting on the same lines. At release time `scripts/changelog.py assemble` turns the fragments
into the release section and deletes them.

## Name

`<PR number>.<section>.md`, for example `123.security.md`.

| Section      | Heading in CHANGELOG.md |
| ------------ | ----------------------- |
| `security`   | Security                |
| `added`      | Added                   |
| `changed`    | Changed                 |
| `deprecated` | Deprecated              |
| `removed`    | Removed                 |
| `fixed`      | Fixed                   |
| `build`      | Build                   |
| `docs`       | Documentation           |

A change that belongs to two sections gets two files (`123.fixed.md`, `123.docs.md`).

## Content

A list of one or more items, written as you would write them in `CHANGELOG.md`: what changed, what
it means for a user or operator, and any upgrade note. Security-relevant changes say what an
attacker could do before and cannot do after. No headings (the file name gives the section), no
trailing whitespace, one newline at the end.

```markdown
- **The driver refuses a config key it does not know.** Before, a misspelt key was ignored; now the
  participant stops at startup and names the key.
```

## Check

```bash
python3 scripts/changelog.py check
```

CI (workflow "Changelog") runs this, and requires a fragment on every pull request that changes
`frost/`, `driver/`, `deploy/` or `scripts/`, unless the pull request carries the label
`no-changelog`. Until 2026-12-18 an edit of `CHANGELOG.md` itself also passes, for pull requests
opened before the switch; the exception is removed with the first release on or after that date.

## Release

`scripts/changelog.py assemble <version> <date>` (see `docs/releasing.md`). It merges the fragments
with whatever is still under `[Unreleased]`, writes `## [<version>] — <date>` above the previous
release and deletes the fragments. For a release candidate use `--keep`: the section is written and the
fragments stay for the final release.
