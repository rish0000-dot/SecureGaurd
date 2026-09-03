/**
 * API Security Rules Registry (OpenAPI / Swagger 2.0 & 3.x)
 */

const API_RULES = {
  'API-001': {
    ruleId: 'API-001',
    framework: 'OpenAPI',
    category: 'Authentication',
    title: 'Missing Authentication Requirement on API Specification',
    severity: 'high',
    cweId: 'CWE-306',
    description: 'API path or operation does not declare any security requirement or security scheme.',
    remediation: 'Declare a top-level security requirement (e.g. BearerAuth, OAuth2, ApiKey) or specify operation-level security.',
    references: ['https://cwe.mitre.org/data/definitions/306.html', 'https://swagger.io/docs/specification/authentication/']
  },
  'API-002': {
    ruleId: 'API-002',
    framework: 'OpenAPI',
    category: 'Authorization',
    title: 'Potentially Missing Authentication on Sensitive Operation',
    severity: 'critical',
    cweId: 'CWE-862',
    description: 'Sensitive state-modifying HTTP operation (POST, PUT, DELETE, PATCH on /admin, /users, /auth, /payments) has empty security requirement.',
    remediation: 'Ensure sensitive endpoints require authenticated roles and explicit authorization scopes.',
    references: ['https://cwe.mitre.org/data/definitions/862.html']
  },
  'API-003': {
    ruleId: 'API-003',
    framework: 'OpenAPI',
    category: 'Transport Security',
    title: 'Insecure Plaintext HTTP Server Definition',
    severity: 'high',
    cweId: 'CWE-319',
    description: 'OpenAPI spec server URL uses unencrypted http:// protocol instead of https://.',
    remediation: 'Update server URLs to use https:// to protect sensitive API traffic in transit.',
    references: ['https://cwe.mitre.org/data/definitions/319.html']
  },
  'API-004': {
    ruleId: 'API-004',
    framework: 'OpenAPI',
    category: 'CORS Security',
    title: 'Wildcard CORS Origin Exposure in API Spec',
    severity: 'medium',
    cweId: 'CWE-942',
    description: 'API response headers or CORS specification allows wildcard ("*") Access-Control-Allow-Origin.',
    remediation: 'Restrict allowed CORS origins to trusted domains rather than using wildcard wildcard (*).',
    references: ['https://cwe.mitre.org/data/definitions/942.html']
  },
  'API-005': {
    ruleId: 'API-005',
    framework: 'OpenAPI',
    category: 'Sensitive Data',
    title: 'Sensitive Parameter Passed in URL Query String',
    severity: 'high',
    cweId: 'CWE-598',
    description: 'API parameter (password, secret, token, access_token, api_key) is configured with in: query.',
    remediation: 'Pass sensitive parameters in request headers (e.g. Authorization header) or encrypted POST body.',
    references: ['https://cwe.mitre.org/data/definitions/598.html']
  },
  'API-006': {
    ruleId: 'API-006',
    framework: 'OpenAPI',
    category: 'Configuration',
    title: 'Missing Global Security Scheme Definitions',
    severity: 'medium',
    cweId: 'CWE-306',
    description: 'OpenAPI spec lacks components.securitySchemes (or securityDefinitions), failing to define standard authentication mechanisms.',
    remediation: 'Define standard securitySchemes (e.g. bearerAuth, apiKey, oauth2) in components section.',
    references: ['https://swagger.io/docs/specification/authentication/']
  }
};

module.exports = { API_RULES };
