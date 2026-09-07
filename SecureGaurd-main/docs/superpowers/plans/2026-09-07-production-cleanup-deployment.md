# SecureGuard Production Cleanup and Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the canonical SecureGuard app repository clean, document production deployment, harden backend hosting configuration, and publish the verified changes.

**Architecture:** Keep the newer nested `SecureGaurd-main/` application as the canonical project and preserve the outer workspace as the Git repository root. Deploy the React/Vite frontend to Vercel and prepare the Express/Prisma backend as a separate long-running web service with environment-managed secrets and explicit frontend CORS configuration.

**Tech Stack:** React, Vite, Express 5, Prisma 7, PostgreSQL, Node.js, Vercel, Render-compatible web service configuration, GitHub.

**Spec:** Approved in chat on 2026-09-07.

## Global Constraints

- Do not commit `.env` files, credentials, generated dependencies, build output, or local Vercel state.
- Preserve existing user changes and do not rewrite unrelated files.
- Use `SecureGaurd-main/` as the application source directory.
- Backend secrets must be configured in the hosting provider dashboard.
- Validate with lint, build, startup regression tests, and Git status before pushing.

---

### Task 1: Consolidate repository structure

**Files:**
- Modify: outer `README.md` to identify the canonical app and commands.
- Modify: outer `.gitignore` to exclude generated artifacts and local deployment state.
- Delete from Git tracking only: obsolete outer duplicate app files after confirming they duplicate the canonical project.
- Preserve: `SecureGaurd-main/` as the single application directory.

- [ ] Confirm the outer duplicate contains no source that is absent from the canonical app.
- [ ] Update ignore rules without changing the user-edited canonical `.gitignore` unexpectedly.
- [ ] Remove only duplicate tracked files from the outer app surface.
- [ ] Check `git status` and verify no secret files are staged.

### Task 2: Add secure backend deployment configuration

**Files:**
- Modify: `SecureGaurd-main/backend/server.js` for production frontend origin configuration and safe startup behavior.
- Modify: `SecureGaurd-main/backend/.env.example` with documented deployment variables.
- Modify: `SecureGaurd-main/backend/package.json` with deterministic production start/build scripts.
- Create: `SecureGaurd-main/backend/render.yaml` as a provider-neutral Render Blueprint using dashboard-managed secrets.
- Create: `SecureGaurd-main/backend/tests/deployment_config.test.js` covering health and deployment configuration behavior.

- [ ] Write the regression test for production CORS origin handling first and verify it fails for the missing behavior.
- [ ] Implement the smallest configuration-driven CORS change and verify the test passes.
- [ ] Configure Prisma client generation during backend build and `npm start` for runtime.
- [ ] Ensure health output stays non-sensitive and the service listens on provider `PORT`.

### Task 3: Rewrite project documentation

**Files:**
- Modify: `SecureGaurd-main/README.md` with architecture, local setup, environment setup, frontend deployment, backend deployment, security checklist, and verification commands.
- Modify: outer `README.md` with a concise repository entry point.
- Create or modify: `SecureGaurd-main/docs/production-readiness-report.md` only where current evidence requires update.

- [ ] Document exact Vercel frontend settings and Render backend settings.
- [ ] Document `VITE_API_URL` and backend CORS configuration without embedding values or secrets.
- [ ] Document database migration and Prisma generation commands.
- [ ] Document deployment limitations, including the need for provider credentials and production environment values.

### Task 4: Validate and publish

**Files:**
- No additional source files unless validation identifies a directly related defect.

- [ ] Run frontend lint and build.
- [ ] Run backend startup and deployment configuration tests.
- [ ] Run production dependency audit and inspect Git diff/status.
- [ ] Commit with `chore: prepare SecureGuard for production deployment`.
- [ ] Push the commit to `origin/main`.
- [ ] Attempt backend provider deployment only when authenticated provider credentials are available; otherwise report the exact remaining external action.
