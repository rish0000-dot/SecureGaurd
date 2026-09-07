const localOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:3000',
  'http://127.0.0.1:3000'
];

function getAllowedOrigins(env = process.env) {
  const configuredOrigins = [env.FRONTEND_URL, ...(env.FRONTEND_URLS || '').split(',')]
    .map((origin) => origin.trim())
    .filter(Boolean)
    .filter((origin) => {
      try {
        return ['http:', 'https:'].includes(new URL(origin).protocol);
      } catch {
        return false;
      }
    });

  return [...new Set([...localOrigins, ...configuredOrigins])];
}

module.exports = { getAllowedOrigins };