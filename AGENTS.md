# Development workflow

Rules for every human and agent working in this repository (`GranatenUdo/ionos-dns-api-cli`, public, MIT). They follow
the owner's standard workflow; `CLAUDE.md` imports this file so Claude Code and Codex read the same rules.

## Plan, adversarial review, then implement

Every assignment follows three ordered steps; do not skip or merge them.

1. **Draft a plan** before touching code or external records: scope, the exact files to change, the verification that
   will prove each claim, and what stays out of scope.
2. **Adversarially review the plan with exactly one independent reviewer agent** before implementation:
   **Claude Code uses one Opus 5.5 agent at `xhigh` effort; Codex uses one Astra agent (`gpt-6-astra`) at `medium`
   effort.** Choose the reviewer for the active harness, not both. Self-review by the parent is no substitute. If the
   required model or effort is unavailable, report the blocker and do not implement or silently substitute another
   reviewer. The reviewer tries to break the plan: missing sources, unverified assumptions about the IONOS API or DNS
   behaviour, secret leaks, test gaps, claims the plan would not evidence. Fix the plan and answer every finding in its
   final text. One review pass per plan; ordinary corrections need no second pass, while a redesign (different
   approach, scope or file set) gets one new review of the revised plan.
3. **Implement the reviewed plan** inline in the parent session, then verify. Deviations found during implementation
   go back to step 1 for the changed part. An implementation helper agent is optional; it works only in the files of
   its step and never commits.

## Worktree per session, pull request per change

- Since v0.1.0, never edit files on the `main` checkout. Create a branch in a separate worktree for each session:
  `git worktree add -b <type>/<short-scope> ../ionos-dns-api-cli-wt-<short-scope> main`.
- Integrate every change through a pull request against `main` (`gh pr create`), never by pushing to `main`.
- After the merge: `git worktree remove ../ionos-dns-api-cli-wt-<short-scope>`, `git branch -d <branch>`, then
  `git pull --ff-only origin main` in the `main` checkout. Do not run `gh pr merge --delete-branch` from the `main`
  checkout; merge on GitHub or from the worktree, then pull.
- **No CI for now.** Validate locally before every commit and PR and state the commands and their results in the PR:
  `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`.

## Secrets and public-repository hygiene

- Never commit API keys, real domain names, zone or record ids, zone exports or captured API responses. Tests, fixtures
  and docs use `example.com`, `example.net`, documentation addresses (192.0.2.0/24, 2001:db8::/32) and made-up ids.
- At use time the key is read only from a private file (owner-only, mode 0600). `login` is the only command that takes
  a key from elsewhere: from a hidden terminal prompt or from a piped standard input, and it stores the key through a
  private temporary file before the first API call. Never add a `--key` argument, a key environment variable, a verbose
  mode that prints headers, or logging of request headers; keep the hidden prompt's signal handling and terminal
  restore (see `src/prompt.rs`) and their pty tests.
- HTTP never follows redirects (a redirect would carry `X-API-Key` elsewhere) and the base-URL override accepts
  loopback addresses only. Keep both, with their tests.

## Tool safety

- v0.1 changes no DNS: GET requests to the API only. Never use `PUT /v1/zones/{id}`: it replaces every record of the zone.
- Write commands (planned for v0.2) must be dry-run by default with `--yes` to apply, refuse NS and SOA, protect mail
  records behind an explicit flag, use a deny-by-default zone allowlist, send whole record sets via PATCH, read the zone
  back afterwards, and be verified live on a scratch record before release.

## Verification is not implementation

State what was tested and how. Never claim a check that did not run; record a skipped or failed check as such.
