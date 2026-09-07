# SecureGuard Workspace

This repository contains the canonical SecureGuard app in `SecureGaurd-main/`.

## Canonical project

Use the nested project for app development, build validation, and deployment setup:

- [SecureGaurd-main/README.md](SecureGaurd-main/README.md)
- [SecureGaurd-main/docs/production-readiness-report.md](SecureGaurd-main/docs/production-readiness-report.md)

## Quick start

```powershell
cd .\SecureGaurd-main
npm install
npm install --prefix backend
npm run build
npm run lint
```

For the complete setup, environment variables, Vercel frontend deployment, Render backend deployment, and security checklist, follow [SecureGaurd-main/README.md](SecureGaurd-main/README.md).
