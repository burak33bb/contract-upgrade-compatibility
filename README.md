# Contract Upgrade Compatibility Oracle

Contract Upgrade Compatibility Oracle is a standalone GenLayer Intelligent Contract primitive for reviewing a proposed Python contract upgrade against a pinned baseline source. It combines deterministic interface analysis with validator-consensus review of semantic code changes and stores each accepted assessment in append-only on-chain history.

## Why GenLayer

Deterministic Python AST analysis can identify interface and state-shape changes, but it cannot reliably determine whether a changed method body preserves the contract's intended behavior. The leader fetches both source files and asks GenLayer to assess the semantic diff. Each validator fetches the same pinned sources, recomputes the interface diff, and independently checks the proposed semantic findings. The contract records state only after the verification passes consensus.

This is not a security audit, formal proof, or guarantee that an upgrade is safe. It is a pre-review aid that makes state/API changes and semantic risks easier to spot before a maintainer upgrades a contract.

## What Is Checked

- Persistent annotated fields: additions, removals, type changes, and relative declaration-order changes.
- Public `gl.public.view` and `gl.public.write` method additions, removals, visibility changes, and signature changes.
- Semantic changes in source code, with source-grounded risk findings from GenLayer validators.
- Source-pair SHA-256 fingerprint and immutable report history.

Both source URLs must be HTTPS raw GitHub URLs pinned to full 40-character commit SHAs, not mutable branch names, so validators inspect the same revisions.

## Outcomes

- `BREAKING_RISK`: a public interface, storage layout, or semantic change may break existing integrations or state.
- `REVIEW_REQUIRED`: compatibility depends on a storage addition, semantic uncertainty, or other unresolved assumption.
- `NO_BREAKING_CHANGE_IDENTIFIED`: no breaking change was identified by this analysis; this does not mean the candidate is safe.

## State and Methods

Deployment pins a contract name, baseline version, and baseline raw-source URL. `get_baseline` exposes that pinned configuration. `assess_candidate` takes a candidate version and pinned raw-source URL plus optional change context. Accepted reports are appended to `reports`; `get_latest_report`, `get_report_count`, and `get_report(id)` expose the history.

The contract does not execute either source file. It parses Python syntax trees for interface facts and submits the source text only as untrusted data to the independent semantic reviewers. Source size and report fields are bounded.

## Example Inputs

```text
contract_name: ExampleVault
baseline_version: v1.0.0
baseline_source_url: https://raw.githubusercontent.com/ORG/REPO/0123456789abcdef0123456789abcdef01234567/contracts/vault.py

candidate_version: v1.1.0
candidate_source_url: https://raw.githubusercontent.com/ORG/REPO/89abcdef0123456789abcdef0123456789abcdef/contracts/vault.py
change_context: Adds a read-only method; storage and write behavior should remain unchanged.
```

Replace `ORG`, `REPO`, the example commit SHAs, and path with real public source references before use.

## Tests

Run `python -m unittest discover -s tests -v`. Tests cover AST extraction, public API and storage changes, conservative outcome aggregation, input validation, and consensus verification wiring. Studio testing is still needed for real GenVM and multi-validator web access.
