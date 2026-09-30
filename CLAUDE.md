# embarch-smp

## Docs

**Four files, not one.** Current truth: [spec.md](../embarch-doc/embarch-smp/spec.md). Why it is that way: [decisions.md](../embarch-doc/embarch-smp/decisions.md) — a decision number addresses this sub-project, not a file. Unresolved: [open.md](../embarch-doc/embarch-smp/open.md). The cross-repo design it serves: [bootload-proposal.md](../embarch-doc/bootload-proposal.md).

Update them proactively per [../embarch-doc/DOC-PROTOCOL.md](../embarch-doc/DOC-PROTOCOL.md) whenever a notable design decision, feature, or status change happens here — §4 says when, §5 says how, and history goes in a `changelog.d/` fragment rather than into a doc.

**This crate is a port.** Every ported file names the Python module it came from (`smp` or `smpclient`) in its header, and `NOTICE` carries the attribution Apache-2.0 requires. Keep both true when adding a file. It never opens a port: every call takes a `Read + Write` the caller opened (decision 2).

## Git

**Work directly on `main` — no feature branches, no PRs (2026-08-25).** Commit and push straight to `main` once the change builds and its tests and `clippy --all-targets -- -D warnings` are clean. This **overrides** the general "if you're on the default branch, branch first" default, for this suite only. It ends when the repo owner explicitly says it does, and on no other condition — not on an agent's read of whether the project has outgrown it. Reasoning, the sequencing rules that keep it safe, and the one case that still warrants a branch: [../embarch-doc/embarch-dev-workflow.md](../embarch-doc/embarch-dev-workflow.md) §6.

**Never run `cargo fmt`** — no EmbArch repo is rustfmt-clean, and the suite does not enforce it ([embarch.md](../embarch-doc/embarch.md) §5).
