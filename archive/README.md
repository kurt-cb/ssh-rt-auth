# archive/ — historical design + docs

Snapshots of the design docs and operator docs that pre-date the
**clean-room mssh rewrite** (see `design/` and `docs/` at the repo
root for current content).

**These files are kept for internal reference only and are not
intended for publication.** They use older naming conventions
("ssh-rt-auth", "Tier 1/2/3", "Phase 1/2", "PoC", etc.) that the
current project documentation no longer uses. Treat them as
*archaeological context*: the technical decisions they describe
are still correct (and frequently more detailed than the new docs
since the new docs were intentionally pared back), but the framing
is outdated.

Use the new docs first:

  - `design/architecture.md`   — what mssh is and how the pieces fit
  - `design/api.md`            — REST + admin API contract
  - `design/security.md`       — trust model + threat analysis
  - `design/future-ideas.md`   — deferred features and design directions

  - `docs/overview.md`         — operator-facing intro
  - `docs/operations.md`       — install, configure, run, troubleshoot

Reach for archived files only when:

  - The new docs are silent on a specific technical detail you need.
  - You want context on *why* a design decision was made (the
    research-style docs `ssh-rt-auth-wrapper-research.md` and
    `ssh-rt-auth-dropped-ideas.md` are the best for this).
  - You need the historical REST API spec while writing migration
    code — `ssh-rt-auth-detailed-rest-api.md` is more exhaustive
    than `design/api.md` aims to be.

When new docs cover a topic fully, the corresponding archive
file should be considered superseded and is fair game for deletion.
