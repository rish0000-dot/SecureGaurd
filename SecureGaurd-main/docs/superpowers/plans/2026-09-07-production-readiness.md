# SecureGuard Production Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Audit and prepare the canonical `SecureGaurd-main` application for deployment while preserving locked business logic and API contracts.

**Architecture:** Treat `SecureGaurd-main` as the only canonical application root. Preserve its existing React/Vite frontend, Express/Prisma backend, scanner utilities, generated Prisma client, tests, and database schema. Apply only evidence-backed repository hygiene, deployment configuration, documentation, or security fixes; each fix must be regression-tested before broader verification.

**Tech Stack:** React 19, Vite, Express 5, Prisma 7, PostgreSQL, Stripe, Node.js, standalone Node verification scripts, Python XGBoost classifier tests.

**Spec:** User-provided SecureGuard final production readiness prompt in the conversation.

## Global Constraints

- Do not rewrite, redesign, refactor, or change working business logic.
- Do not change API routes, response formats, database fields, migrations, or business rules.
- Do not expose, print, commit, or add real secrets.
- Do not run destructive database commands or repository code from scanned content.
- Do not use `npm audit fix --force`.
- Do not delete tests, migrations, lockfiles, required generated assets, or deployment configuration.
- Report unverified areas as `REQUIRES MANUAL VERIFICATION`; never invent results.

---

### Task 1: Establish the audit baseline

**Files:**
- Inspect only: `git status`, `git ls-files`, `package.json`, `backend/package.json`, `.gitignore`, `backend/.env.example`, `backend/server.js`, `README.md`, `SECURITY_AUDIT.md`.
- Create: `docs/superpowers/plans/2026-09-07-production-readiness.md`.
- Create later: `docs/production-readiness-report.md`.

**Interfaces:**
- Produces a verified list of tracked artifacts, available scripts, environment variable names, route/startup surfaces, and test commands for later tasks.

- [ ] **Step 1: Record repository state**

Run from `SecureGaurd-main`:

```powershell
git status --short --branch
git ls-files
git log -5 --oneline
```

Expected: the baseline is captured without modifying files; unrelated existing changes are preserved.

- [ ] **Step 2: Inventory environment-like files without printing values**

```powershell
Get-ChildItem -Recurse -Force -File | Where-Object { $_.Name -match '^\.env' -and $_.FullName -notmatch '\\node_modules\\|\\.git\\' } | Select-Object FullName
```

Inspect only variable names in examples; never print secret-bearing values.

- [ ] **Step 3: Discover all executable checks**

Read package scripts and enumerate `backend/tests/*.js`, Python classifier tests, Prisma configuration, and any CI/deployment files. Do not run tests before required environment prerequisites are understood.

- [ ] **Step 4: Create an audit evidence ledger**

Record each check as `PASSED`, `FAILED`, `NOT APPLICABLE`, or `REQUIRES MANUAL VERIFICATION`, including the exact command and safe summary. Do not include credentials or secret values.

### Task 2: Verify repository hygiene and secrets handling

**Files:**
- Modify only if evidence requires: `.gitignore`, `backend/.gitignore`, `backend/.env.example`.
- Inspect: tracked `.vite`, classifier artifacts, docs binaries, logs, local env files, frontend source, backend source, Git history.

**Interfaces:**
- Produces a clean ignore policy and a secret-scan result without changing application behavior.

- [ ] **Step 1: Confirm generated artifacts and duplicate roots**

Check tracked `.vite` paths, `__pycache__`, build output, logs, and classifier model duplication. Search imports and scripts before removing anything. Verify whether root-level `src/` and `backend/` are separate legacy applications; do not delete them in this task unless every reference and deployment dependency is disproven.

- [ ] **Step 2: Scan tracked text safely**

Search source and history for secret patterns such as `sk_`, `AIza`, `ghp_`, `github_pat_`, private-key markers, and credential assignments. Redact matches in all reports. If a real secret is found, replace it with an environment variable only if the code path requires it and report rotation as mandatory.

- [ ] **Step 3: Remove only confirmed generated clutter**

If `.vite` or Python `__pycache__` is confirmed generated and not required at runtime, remove it from the working tree and add narrowly scoped ignore entries. Preserve model files, fixtures, docs, lockfiles, migrations, and required assets.

- [ ] **Step 4: Validate hygiene changes**

Run:

```powershell
git status --short
git check-ignore -v .vite/deps/_metadata.json backend/services/fp-classifier/__pycache__/service.cpython-314.pyc
```

Expected: only intentional cleanup appears in the diff and generated files are ignored.

### Task 3: Audit and harden deployment configuration only where required

**Files:**
- Inspect first: `backend/server.js`, `backend/.env.example`, `vite.config.js`, `package.json`, `backend/package.json`, `backend/prisma.config.ts`.
- Modify only when a concrete deployment/security gap is demonstrated.
- Add/update only if needed: root deployment documentation, `.env.example`, or a safe health endpoint.

**Interfaces:**
- Preserves all existing route mounts and webhook ordering.
- Any health check must return only `{ "status": "ok" }` and must not expose credentials or internals.

- [ ] **Step 1: Verify production configuration inputs**

Map actual environment variables from backend routes/services and frontend `import.meta.env` usage. Confirm production CORS is environment-based or document the required manual configuration. Do not blindly replace localhost development origins.

- [ ] **Step 2: Verify security boundaries**

Inspect auth/RBAC middleware, organization filters, Stripe webhook raw-body handling, error responses, logging, external URL fetching, file paths, parser invocation, and AI calls. Only edit code for a clearly identified vulnerability or startup blocker.

- [ ] **Step 3: Add the smallest compatible deployment fix**

If a missing health endpoint or production startup blocker is confirmed, add the smallest route/config change without altering existing contracts. Add a focused regression test before implementation where the repository has a suitable test harness.

- [ ] **Step 4: Run focused validation immediately**

Run the narrow test or startup check covering the changed surface. Repair only that slice if it fails, then rerun the same check.

### Task 4: Make deployment documentation actionable

**Files:**
- Modify: `README.md`.
- Create or modify only as needed: `.env.example` at the canonical root.
- Preserve: `SECURITY_AUDIT.md`, `LIMITATIONS.md`, existing feature documentation.

**Interfaces:**
- Documentation names actual scripts and actual environment variables only.
- Documentation contains no secret values and no unsupported deployment claims.

- [ ] **Step 1: Document requirements and setup**

Document Node/Python prerequisites, dependency installation, environment setup, Prisma client generation/migration strategy, and frontend/backend development commands based on actual package scripts.

- [ ] **Step 2: Document verification and production startup**

Document the real lint/build/test commands, backend startup, health check, Stripe webhook configuration, CORS/frontend origin configuration, and classifier prerequisites. Mark unavailable checks as manual instead of fabricating commands.

- [ ] **Step 3: Validate documentation commands**

Run every documented command that is safe in the current environment, especially frontend build, lint, Prisma validation/generation, and backend startup with test-safe configuration.

### Task 5: Execute full verification and produce the final report

**Files:**
- Create: `docs/production-readiness-report.md`.
- Modify application files only if a verification failure proves a required deployment/security fix.

**Interfaces:**
- Report includes final tree, files removed/moved/renamed, intentionally untouched high-risk files, secret scan, dependency audit, security categories, test categories, build/startup/health results, limitations, and exactly one deployment verdict.

- [ ] **Step 1: Run dependency audit without forced upgrades**

Run `npm audit` in the canonical root and backend package where applicable. Classify findings by severity and production reachability; do not apply blind upgrades.

- [ ] **Step 2: Run static and build checks**

Run:

```powershell
npm run lint
npm run build
npx prisma validate --schema backend/prisma/schema.prisma
```

Use the repository's actual Prisma invocation if the local CLI requires it.

- [ ] **Step 3: Run all existing verification scripts**

Execute every available backend verification script and Python classifier test using safe test configuration. Do not skip failing tests; record environmental blockers separately from application failures.

- [ ] **Step 4: Run production-style startup and health verification**

Start the backend with non-production test-safe environment values, verify startup and `GET /health` if available, then stop the process. Do not leave unnecessary processes running.

- [ ] **Step 5: Write the evidence-based report**

Use only observed results. Use `READY FOR DEPLOYMENT` only if all blocking criteria pass; otherwise use `READY WITH WARNINGS` or `NOT READY FOR DEPLOYMENT` and list the exact blockers.

- [ ] **Step 6: Final diff and tree review**

Run `git diff --check`, `git status --short`, and print the final directory tree. Confirm no unrelated business-logic edits or secret values were introduced.
