const fs = require('fs');
const yaml = require('js-yaml');
const { IAC_RULES } = require('./rules/iacRules');

function createK8sFinding(ruleId, filePath, lineStart, codeSnippet, resourceKind = 'Pod', resourceName = 'unknown') {
  const rule = IAC_RULES[ruleId];
  if (!rule) return null;

  return {
    ruleId: rule.ruleId,
    cweId: rule.cweId,
    type: 'iac',
    severity: rule.severity,
    title: rule.title,
    description: rule.description,
    filePath,
    lineStart: lineStart || 1,
    lineEnd: lineStart || 1,
    codeSnippet: codeSnippet ? codeSnippet.trim() : `${resourceKind}/${resourceName}`,
    status: 'open',
    mlFeatures: {
      framework: rule.framework,
      category: rule.category,
      resourceType: resourceKind,
      resourceName,
      ruleId: rule.ruleId,
      cweId: rule.cweId,
      isIaC: true
    }
  };
}

/**
 * Robust Kubernetes YAML/YML Scanner using js-yaml multi-doc parser
 */
function scanKubernetesFile(fullPath, relPath) {
  const findings = [];
  try {
    const content = fs.readFileSync(fullPath, 'utf8');
    if (!content.trim()) return findings;

    // Is it a Kubernetes manifest? Check apiVersion / kind presence
    if (!/apiVersion\s*:/i.test(content) || !/kind\s*:/i.test(content)) {
      return findings; // Skip generic YAMLs that are not K8s manifests
    }

    let documents = [];
    try {
      // Safe multi-document load with schema limits
      yaml.loadAll(content, (doc) => {
        if (doc && typeof doc === 'object') {
          documents.push(doc);
        }
      }, { schema: yaml.DEFAULT_SAFE_SCHEMA, json: true });
    } catch (parseErr) {
      // Return structured parser warning without crashing scan
      findings.push({
        ruleId: 'K8S-PARSER-WARN',
        cweId: 'CWE-20',
        type: 'iac',
        severity: 'info',
        title: 'Malformed Kubernetes Manifest',
        description: `Parser Warning: Could not parse YAML document safely in ${relPath}: ${parseErr.message}`,
        filePath: relPath,
        lineStart: 1,
        lineEnd: 1,
        codeSnippet: content.slice(0, 100),
        status: 'open',
        mlFeatures: { framework: 'Kubernetes', isIaC: true }
      });
      return findings;
    }

    const lines = content.split('\n');

    for (const doc of documents) {
      const kind = doc.kind || 'Manifest';
      const name = doc.metadata?.name || 'unnamed';

      // PodSpec extraction (Deployment, DaemonSet, StatefulSet, ReplicaSet, Job, Pod)
      let podSpec = doc.spec;
      if (doc.spec?.template?.spec) {
        podSpec = doc.spec.template.spec;
      }
      if (!podSpec) continue;

      // K8S-003 Host Network
      if (podSpec.hostNetwork === true) {
        const lineNum = lines.findIndex(l => l.includes('hostNetwork')) + 1 || 1;
        findings.push(createK8sFinding('K8S-003', relPath, lineNum, 'hostNetwork: true', kind, name));
      }

      // K8S-004 Host PID
      if (podSpec.hostPID === true) {
        const lineNum = lines.findIndex(l => l.includes('hostPID')) + 1 || 1;
        findings.push(createK8sFinding('K8S-004', relPath, lineNum, 'hostPID: true', kind, name));
      }

      // K8S-005 Dangerous HostPath Volume Mount
      if (Array.isArray(podSpec.volumes)) {
        for (const vol of podSpec.volumes) {
          if (vol.hostPath) {
            const lineNum = lines.findIndex(l => l.includes('hostPath')) + 1 || 1;
            findings.push(createK8sFinding('K8S-005', relPath, lineNum, `hostPath: ${vol.hostPath.path || ''}`, kind, name));
          }
        }
      }

      const containers = [
        ...(Array.isArray(podSpec.containers) ? podSpec.containers : []),
        ...(Array.isArray(podSpec.initContainers) ? podSpec.initContainers : [])
      ];

      for (const container of containers) {
        const cName = container.name || 'container';
        const secContext = container.securityContext || {};
        const podSecContext = podSpec.securityContext || {};

        // K8S-001 Privileged Container
        if (secContext.privileged === true) {
          const lineNum = lines.findIndex(l => l.includes('privileged')) + 1 || 1;
          findings.push(createK8sFinding('K8S-001', relPath, lineNum, `privileged: true (${cName})`, kind, name));
        }

        // K8S-002 Root User Execution
        if (secContext.runAsUser === 0 || podSecContext.runAsUser === 0 || (!secContext.runAsNonRoot && !podSecContext.runAsNonRoot)) {
          const lineNum = lines.findIndex(l => l.includes('runAsUser') || l.includes('runAsNonRoot')) + 1 || 1;
          findings.push(createK8sFinding('K8S-002', relPath, lineNum, `runAsNonRoot missing or runAsUser: 0 (${cName})`, kind, name));
        }

        // K8S-006 Missing Resource Limits
        if (!container.resources || !container.resources.limits) {
          findings.push(createK8sFinding('K8S-006', relPath, 1, `resources.limits missing (${cName})`, kind, name));
        }

        // K8S-007 Insecure Capabilities
        const addedCaps = secContext.capabilities?.add || [];
        if (Array.isArray(addedCaps) && addedCaps.some(c => ['SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'ALL'].includes(c))) {
          const lineNum = lines.findIndex(l => l.includes('capabilities')) + 1 || 1;
          findings.push(createK8sFinding('K8S-007', relPath, lineNum, `capabilities.add: ${JSON.stringify(addedCaps)} (${cName})`, kind, name));
        }

        // K8S-008 Allow Privilege Escalation
        if (secContext.allowPrivilegeEscalation === true) {
          const lineNum = lines.findIndex(l => l.includes('allowPrivilegeEscalation')) + 1 || 1;
          findings.push(createK8sFinding('K8S-008', relPath, lineNum, `allowPrivilegeEscalation: true (${cName})`, kind, name));
        }

        // K8S-009 Plaintext Secret Values in ENV
        if (Array.isArray(container.env)) {
          for (const envVar of container.env) {
            if (envVar.value && typeof envVar.value === 'string') {
              if (/(?:password|secret|key|token|passwd)/i.test(envVar.name) && envVar.value.length > 3) {
                const lineNum = lines.findIndex(l => l.includes(envVar.name)) + 1 || 1;
                // Redact secret value in output
                const redacted = envVar.value.substring(0, 2) + '****';
                findings.push(createK8sFinding('K8S-009', relPath, lineNum, `env ${envVar.name} = "${redacted}"`, kind, name));
              }
            }
          }
        }
      }
    }
  } catch (err) {
    // Malformed file handling
  }

  return findings;
}

module.exports = { scanKubernetesFile };
