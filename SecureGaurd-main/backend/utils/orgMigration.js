/**
 * Safe Auto-Migration Utility for Teams & Organizations
 *
 * Ensures all existing users have a default personal organization,
 * sets their role to OWNER, and attaches all pre-existing repositories,
 * scans, and compliance reports to their organization.
 */

const prisma = require('../prismaClient');

function slugify(text) {
  return text
    .toString()
    .toLowerCase()
    .trim()
    .replace(/\s+/g, '-')       // Replace spaces with -
    .replace(/[^\w\-]+/g, '')   // Remove all non-word chars
    .replace(/\-\-+/g, '-');    // Replace multiple - with single -
}

async function ensureDefaultOrganization(userId) {
  if (!userId) return null;

  // Check if user already has an organization membership
  const existingMembership = await prisma.organizationMembership.findFirst({
    where: { userId },
    include: { organization: true }
  });

  if (existingMembership) {
    return existingMembership.organization;
  }

  // Retrieve user details to form organization name
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) return null;

  const baseName = `${user.firstName}'s Workspace`;
  let slug = `${slugify(user.firstName)}-${user.id}`;
  
  // Ensure unique slug
  let suffix = 0;
  while (await prisma.organization.findUnique({ where: { slug } })) {
    suffix++;
    slug = `${slugify(user.firstName)}-${user.id}-${suffix}`;
  }

  // Create organization and link existing resources atomically in a transaction
  return await prisma.$transaction(async (tx) => {
    const org = await tx.organization.create({
      data: {
        name: baseName,
        slug: slug,
      }
    });

    // Create OWNER membership
    await tx.organizationMembership.create({
      data: {
        userId: user.id,
        organizationId: org.id,
        role: 'OWNER',
      }
    });

    // Attach unassociated user repositories
    await tx.repository.updateMany({
      where: { userId: user.id, organizationId: null },
      data: { organizationId: org.id }
    });

    // Attach unassociated user scans
    await tx.scan.updateMany({
      where: { userId: user.id, organizationId: null },
      data: { organizationId: org.id }
    });

    // Attach unassociated compliance reports
    await tx.complianceReport.updateMany({
      where: { userId: user.id, organizationId: null },
      data: { organizationId: org.id }
    });

    // Log audit event
    await tx.auditLog.create({
      data: {
        organizationId: org.id,
        actorId: user.id,
        action: 'ORGANIZATION_CREATED',
        targetType: 'ORGANIZATION',
        targetId: String(org.id),
        details: { name: org.name, slug: org.slug, isAutoMigrated: true }
      }
    });

    return org;
  });
}

async function migrateAllExistingData() {
  const users = await prisma.user.findMany({ select: { id: true } });
  let count = 0;
  for (const user of users) {
    await ensureDefaultOrganization(user.id);
    count++;
  }
  return count;
}

module.exports = {
  ensureDefaultOrganization,
  migrateAllExistingData
};
