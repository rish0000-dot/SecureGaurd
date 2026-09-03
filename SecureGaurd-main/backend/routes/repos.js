const express = require('express');
const router = express.Router();
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { requireOrgContext, requireOrgRole, createAuditLog } = require('../middleware/rbac');
const { checkCanAddRepository } = require('../services/billingService');

// All repo routes require auth and organization context
router.use(authMiddleware);
router.use(requireOrgContext);

// GET /api/repos — list all repos for the active organization
router.get('/', async (req, res) => {
  try {
    const repos = await prisma.repository.findMany({
      where: { organizationId: req.organizationId },
      include: {
        scans: {
          orderBy: { createdAt: 'desc' },
          take: 1, // last scan only
        },
        _count: { select: { scans: true } },
      },
      orderBy: { updatedAt: 'desc' },
    });
    res.json(repos);
  } catch (err) {
    console.error('Error fetching repos:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/repos — add a new repository to the organization
router.post('/', requireOrgRole(['OWNER', 'ADMIN', 'DEVELOPER']), async (req, res) => {
  const { name, fullName, url, platform, language } = req.body;
  if (!name || !url) return res.status(400).json({ message: 'name and url are required' });

  try {
    // Entitlement Check: Repository Limit
    const limitCheck = await checkCanAddRepository(req.organizationId);
    if (!limitCheck.allowed) {
      await createAuditLog(
        req.organizationId,
        req.userId,
        'USAGE_LIMIT_REACHED',
        'ORGANIZATION',
        String(req.organizationId),
        { resource: 'REPOSITORY', limit: limitCheck.usage?.limit }
      );
      return res.status(403).json({
        error: limitCheck.reason,
        message: limitCheck.message,
        usage: limitCheck.usage
      });
    }
    const repo = await prisma.repository.create({
      data: {
        userId: req.userId,
        organizationId: req.organizationId,
        name: name.trim(),
        fullName: fullName || name.trim(),
        url: url.trim(),
        platform: platform || 'manual',
        language: language || null,
      },
    });

    await createAuditLog(
      req.organizationId,
      req.userId,
      'REPOSITORY_ADDED',
      'REPOSITORY',
      String(repo.id),
      { name: repo.name, fullName: repo.fullName, platform: repo.platform }
    );

    res.status(201).json(repo);
  } catch (err) {
    if (err.code === 'P2002') {
      return res.status(400).json({ message: 'Repository already connected' });
    }
    console.error('Error creating repo:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// DELETE /api/repos/:id — remove a repository (OWNER or ADMIN only)
router.delete('/:id', requireOrgRole(['OWNER', 'ADMIN']), async (req, res) => {
  const repoId = parseInt(req.params.id);
  if (isNaN(repoId)) return res.status(400).json({ message: 'Invalid repository ID' });

  try {
    const repo = await prisma.repository.findFirst({
      where: { id: repoId, organizationId: req.organizationId },
    });
    if (!repo) return res.status(404).json({ message: 'Repository not found' });

    await prisma.repository.delete({ where: { id: repo.id } });

    await createAuditLog(
      req.organizationId,
      req.userId,
      'REPOSITORY_REMOVED',
      'REPOSITORY',
      String(repo.id),
      { name: repo.name, fullName: repo.fullName }
    );

    res.json({ message: 'Repository removed' });
  } catch (err) {
    console.error('Error removing repo:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
