const fs = require('fs');
const yaml = require('js-yaml');
const { API_RULES } = require('./rules/apiRules');

function createAPIFinding(ruleId, filePath, lineStart, codeSnippet, pathName = '/', httpMethod = 'GET') {
  const rule = API_RULES[ruleId];
  if (!rule) return null;

  return {
    ruleId: rule.ruleId,
    cweId: rule.cweId,
    type: 'api',
    severity: rule.severity,
    title: rule.title,
    description: rule.description,
    filePath,
    lineStart: lineStart || 1,
    lineEnd: lineStart || 1,
    codeSnippet: codeSnippet ? codeSnippet.trim() : `${httpMethod.toUpperCase()} ${pathName}`,
    status: 'open',
    mlFeatures: {
      framework: rule.framework,
      category: rule.category,
      resourceType: 'API Endpoint',
      resourceName: `${httpMethod.toUpperCase()} ${pathName}`,
      ruleId: rule.ruleId,
      cweId: rule.cweId,
      isApi: true
    }
  };
}

/**
 * OpenAPI 2.0 (Swagger) & 3.x Specification Security Scanner
 */
function scanAPISpecFile(fullPath, relPath) {
  const findings = [];
  try {
    const content = fs.readFileSync(fullPath, 'utf8');
    if (!content.trim()) return findings;

    let spec = null;
    if (relPath.endsWith('.json')) {
      try { spec = JSON.parse(content); } catch (e) { return findings; }
    } else {
      try {
        spec = yaml.load(content, { schema: yaml.DEFAULT_SAFE_SCHEMA, json: true });
      } catch (e) {
        return findings;
      }
    }

    if (!spec || typeof spec !== 'object') return findings;
    
    // Check if it is an OpenAPI / Swagger document
    const isOpenAPI3 = spec.openapi && String(spec.openapi).startsWith('3');
    const isSwagger2 = spec.swagger && String(spec.swagger).startsWith('2');

    if (!isOpenAPI3 && !isSwagger2) {
      return findings; // Skip generic YAML/JSON
    }

    const lines = content.split('\n');

    // 1. API-003 Insecure HTTP Server URLs
    const servers = spec.servers || (spec.schemes ? spec.schemes.map(s => `${s}://${spec.host || 'localhost'}`) : []);
    for (const server of servers) {
      const url = typeof server === 'string' ? server : server.url || '';
      if (url.startsWith('http://')) {
        const lineNum = lines.findIndex(l => l.includes(url)) + 1 || 1;
        findings.push(createAPIFinding('API-003', relPath, lineNum, `Server URL: ${url}`));
      }
    }

    // 2. API-006 Missing Security Scheme Definitions
    const securitySchemes = spec.components?.securitySchemes || spec.securityDefinitions || {};
    const hasSchemes = Object.keys(securitySchemes).length > 0;
    if (!hasSchemes) {
      findings.push(createAPIFinding('API-006', relPath, 1, 'Missing securitySchemes or securityDefinitions'));
    }

    const globalSecurity = Array.isArray(spec.security) ? spec.security : [];
    const hasGlobalSecurity = globalSecurity.length > 0;

    // 3. Scan Paths & Operations
    const paths = spec.paths || {};
    const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head'];

    for (const [pathName, pathItem] of Object.entries(paths)) {
      if (!pathItem || typeof pathItem !== 'object') continue;

      for (const method of HTTP_METHODS) {
        const op = pathItem[method];
        if (!op || typeof op !== 'object') continue;

        const opSecurity = Array.isArray(op.security) ? op.security : null;
        const effectiveSecurity = opSecurity !== null ? opSecurity : globalSecurity;
        const isPublicOperation = effectiveSecurity.length === 0;

        // API-001 Missing Authentication
        if (isPublicOperation && !hasGlobalSecurity) {
          const lineNum = lines.findIndex(l => l.includes(pathName)) + 1 || 1;
          findings.push(createAPIFinding('API-001', relPath, lineNum, `${method.toUpperCase()} ${pathName}`, pathName, method));
        }

        // API-002 Potentially Missing Auth on Sensitive Operation
        const isSensitivePath = /(?:admin|user|auth|payment|delete|scan|config|secret)/i.test(pathName);
        const isStateModifying = ['post', 'put', 'delete', 'patch'].includes(method);
        if (isSensitivePath && isStateModifying && isPublicOperation) {
          const lineNum = lines.findIndex(l => l.includes(pathName)) + 1 || 1;
          findings.push(createAPIFinding('API-002', relPath, lineNum, `${method.toUpperCase()} ${pathName}`, pathName, method));
        }

        // API-005 Sensitive Parameter in Query
        const parameters = [...(Array.isArray(pathItem.parameters) ? pathItem.parameters : []), ...(Array.isArray(op.parameters) ? op.parameters : [])];
        for (const param of parameters) {
          if (param.in === 'query' && /(?:password|secret|token|api_key|access_token)/i.test(param.name)) {
            const lineNum = lines.findIndex(l => l.includes(param.name)) + 1 || 1;
            findings.push(createAPIFinding('API-005', relPath, lineNum, `Parameter ${param.name} in query string`, pathName, method));
          }
        }
      }
    }

    // 4. API-004 Wildcard CORS Check
    if (content.includes('Access-Control-Allow-Origin') && content.includes('*')) {
      const lineNum = lines.findIndex(l => l.includes('Access-Control-Allow-Origin')) + 1 || 1;
      findings.push(createAPIFinding('API-004', relPath, lineNum, 'Access-Control-Allow-Origin: *'));
    }

  } catch (err) {
    // Malformed file handling
  }

  return findings;
}

module.exports = { scanAPISpecFile };
