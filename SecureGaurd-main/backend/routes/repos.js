const express = require('express');
const router = express.Router();
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');

// All repo routes require auth
router.use(authMiddleware);

// GET /api/repos — list all repos for the logged-in user
router.get('/', async (req, res) => {
  try {
    const repos = await prisma.repository.findMany({
      where: { userId: req.userId },
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
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/repos — add a new repository manually
router.post('/', async (req, res) => {
  const { name, fullName, url, platform, language } = req.body;
  if (!name || !url) return res.status(400).json({ message: 'name and url are required' });

  try {
    const repo = await prisma.repository.create({
      data: {
        userId: req.userId,
        name: name.trim(),
        fullName: fullName || name.trim(),
        url: url.trim(),
        platform: platform || 'manual',
        language: language || null,
      },
    });
    res.status(201).json(repo);
  } catch (err) {
    if (err.code === 'P2002') {
      return res.status(400).json({ message: 'Repository already connected' });
    }
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// DELETE /api/repos/:id — remove a repository
router.delete('/:id', async (req, res) => {
  try {
    const repo = await prisma.repository.findFirst({
      where: { id: parseInt(req.params.id), userId: req.userId },
    });
    if (!repo) return res.status(404).json({ message: 'Repository not found' });

    await prisma.repository.delete({ where: { id: repo.id } });
    res.json({ message: 'Repository removed' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
