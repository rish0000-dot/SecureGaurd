const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { createAuditLog } = require('../middleware/rbac');

// ── GET /api/invitations/:token — Inspect invitation ─────────────────────────
router.get('/:token', async (req, res) => {
  const rawToken = req.params.token;
  if (!rawToken) return res.status(400).json({ message: 'Token is required' });

  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

  try {
    const invitation = await prisma.organizationInvitation.findUnique({
      where: { tokenHash },
      include: {
        organization: { select: { id: true, name: true, slug: true } },
        invitedBy: { select: { firstName: true, lastName: true, email: true } }
      }
    });

    if (!invitation) {
      return res.status(404).json({ message: 'Invalid or non-existent invitation' });
    }

    if (invitation.status !== 'PENDING') {
      return res.status(400).json({ message: `Invitation has already been ${invitation.status.toLowerCase()}` });
    }

    if (invitation.expiresAt < new Date()) {
      await prisma.organizationInvitation.update({
        where: { id: invitation.id },
        data: { status: 'EXPIRED' }
      });
      return res.status(400).json({ message: 'Invitation has expired' });
    }

    res.json({
      organization: invitation.organization,
      invitedEmail: invitation.invitedEmail,
      role: invitation.role,
      invitedBy: invitation.invitedBy,
      expiresAt: invitation.expiresAt
    });
  } catch (err) {
    console.error('Error inspecting invitation:', err);
    res.status(500).json({ message: 'Server error inspecting invitation' });
  }
});

// ── POST /api/invitations/:token/accept — Accept invitation ──────────────────
router.post('/:token/accept', authMiddleware, async (req, res) => {
  const rawToken = req.params.token;
  if (!rawToken) return res.status(400).json({ message: 'Token is required' });

  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

  try {
    const invitation = await prisma.organizationInvitation.findUnique({
      where: { tokenHash },
      include: { organization: true }
    });

    if (!invitation) {
      return res.status(404).json({ message: 'Invalid or non-existent invitation' });
    }

    if (invitation.status !== 'PENDING') {
      return res.status(400).json({ message: `Invitation has already been ${invitation.status.toLowerCase()}` });
    }

    if (invitation.expiresAt < new Date()) {
      await prisma.organizationInvitation.update({
        where: { id: invitation.id },
        data: { status: 'EXPIRED' }
      });
      return res.status(400).json({ message: 'Invitation has expired' });
    }

    // Check if user is already a member
    const existingMembership = await prisma.organizationMembership.findUnique({
      where: {
        userId_organizationId: {
          userId: req.userId,
          organizationId: invitation.organizationId
        }
      }
    });

    if (existingMembership) {
      await prisma.organizationInvitation.update({
        where: { id: invitation.id },
        data: { status: 'ACCEPTED' }
      });
      return res.json({
        message: 'You are already a member of this organization',
        organization: invitation.organization,
        membership: existingMembership
      });
    }

    // Accept invitation and create membership atomically
    const result = await prisma.$transaction(async (tx) => {
      await tx.organizationInvitation.update({
        where: { id: invitation.id },
        data: { status: 'ACCEPTED' }
      });

      const membership = await tx.organizationMembership.create({
        data: {
          userId: req.userId,
          organizationId: invitation.organizationId,
          role: invitation.role
        }
      });

      return membership;
    });

    await createAuditLog(
      invitation.organizationId,
      req.userId,
      'MEMBER_ACCEPTED',
      'USER',
      String(req.userId),
      { role: invitation.role, invitedEmail: invitation.invitedEmail }
    );

    res.json({
      message: 'Invitation accepted successfully',
      organization: {
        id: invitation.organization.id,
        name: invitation.organization.name,
        slug: invitation.organization.slug
      },
      membership: {
        id: result.id,
        role: result.role,
        createdAt: result.createdAt
      }
    });
  } catch (err) {
    console.error('Error accepting invitation:', err);
    res.status(500).json({ message: 'Server error accepting invitation' });
  }
});

module.exports = router;
