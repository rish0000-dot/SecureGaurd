const prisma = require('../prismaClient');

async function verifySchema() {
  try {
    const columns = await prisma.$queryRaw`
      SELECT column_name, data_type, column_default, is_nullable
      FROM information_schema.columns
      WHERE table_name = 'User'
      ORDER BY ordinal_position;
    `;
    console.log('--- PostgreSQL User Table Columns ---');
    console.table(columns);

    const hasColumn = columns.some(c => c.column_name === 'onboardingCompleted');
    if (hasColumn) {
      console.log('✅ CONFIRMED: "onboardingCompleted" column is present in PostgreSQL User table!');
    } else {
      console.error('❌ FAIL: "onboardingCompleted" column is NOT present.');
    }
  } catch (err) {
    console.error('Error verifying database schema:', err);
  } finally {
    await prisma.$disconnect();
  }
}

verifySchema();
