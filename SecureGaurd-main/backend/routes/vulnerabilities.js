const express = require('express');
const router = express.Router();
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');

router.use(authMiddleware);

// GET /api/vulnerabilities — all open vulns for this user with filters
router.get('/', async (req, res) => {
  const { severity, status, scanId } = req.query;

  try {
    const where = {
      scan: { userId: req.userId },
      ...(severity && { severity }),
      ...(status  && { status  }),
      ...(scanId  && { scanId: parseInt(scanId) }),
    };

    const vulns = await prisma.vulnerability.findMany({
      where,
      include: {
        scan: { select: { id: true, repository: { select: { name: true } } } },
      },
      orderBy: [
        { severity: 'asc' },   // critical first
        { createdAt: 'desc' },
      ],
      take: 100,
    });

    res.json(vulns);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// PATCH /api/vulnerabilities/:id/status — mark as fixed / ignored / false_positive
router.patch('/:id/status', async (req, res) => {
  const { status } = req.body;
  const allowed = ['open', 'fixed', 'ignored', 'false_positive'];
  if (!allowed.includes(status)) return res.status(400).json({ message: 'Invalid status' });

  try {
    const vuln = await prisma.vulnerability.findFirst({
      where: { id: parseInt(req.params.id), scan: { userId: req.userId } },
    });
    if (!vuln) return res.status(404).json({ message: 'Vulnerability not found' });

    let userLabel = undefined;
    if (status === 'ignored' || status === 'false_positive') {
      userLabel = 'false_positive';
    } else if (status === 'fixed') {
      userLabel = 'real';
    }

    const updated = await prisma.vulnerability.update({
      where: { id: vuln.id },
      data: {
        status,
        ...(userLabel && { userLabel })
      },
    });
    res.json(updated);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// PATCH /api/vulnerabilities/:id/label — explicit ML feedback (for "Confirm Real" / "Mark False Positive" buttons in UI)
// This records developer judgment without changing the status, so retraining gets clean signal.
router.patch('/:id/label', async (req, res) => {
  const { label } = req.body;
  const allowed = ['real', 'false_positive'];
  if (!allowed.includes(label)) return res.status(400).json({ message: 'Invalid label. Must be "real" or "false_positive"' });

  try {
    const vuln = await prisma.vulnerability.findFirst({
      where: { id: parseInt(req.params.id), scan: { userId: req.userId } },
    });
    if (!vuln) return res.status(404).json({ message: 'Vulnerability not found' });

    const updated = await prisma.vulnerability.update({
      where: { id: vuln.id },
      data: { userLabel: label },
    });
    res.json({ success: true, id: updated.id, userLabel: updated.userLabel });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
