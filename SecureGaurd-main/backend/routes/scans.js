const express = require('express');
const router = express.Router();
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const path = require('path');
const { runSecurityScan } = require('../utils/securityScanner');

// GET /api/scans/export-feedback — export all user feedback labels for retraining (bypass auth if valid api key is present)
router.get('/export-feedback', async (req, res, next) => {
  const apiKey = req.headers['x-secureguard-key'];
  if (process.env.CLASSIFIER_API_KEY && apiKey === process.env.CLASSIFIER_API_KEY) {
    return next();
  }
  authMiddleware(req, res, next);
}, async (req, res) => {
  try {
    const vulns = await prisma.vulnerability.findMany({
      where: {
        userLabel: { not: null },
        mlFeatures: { not: null }
      },
      select: {
        userLabel: true,
        mlFeatures: true
      }
    });

    const formatted = vulns.map(v => {
      const features = typeof v.mlFeatures === 'string' ? JSON.parse(v.mlFeatures) : v.mlFeatures;
      return {
        rule_id: features.rule_id || '',
        cwe_id: features.cwe_id || '',
        is_string_concat: features.is_string_concat || 0,
        is_parameterized_query: features.is_parameterized_query || 0,
        has_sanitizer_nearby: features.has_sanitizer_nearby || 0,
        in_test_file: features.in_test_file || 0,
        is_in_vendor_or_generated_dir: features.is_in_vendor_or_generated_dir || 0,
        taint_source_distance: features.taint_source_distance || 5,
        function_complexity: features.function_complexity || 1,
        code_snippet_length: features.code_snippet_length || 0,
        variable_name_entropy: features.variable_name_entropy || 0.0,
        is_user_input_direct: features.is_user_input_direct || 0,
        has_type_validation: features.has_type_validation || 0,
        is_third_party_lib_call: features.is_third_party_lib_call || 0,
        same_finding_seen_before_count: features.same_finding_seen_before_count || 0,
        developer_dismissed_similar_before: features.developer_dismissed_similar_before || 0,
        file_change_frequency: features.file_change_frequency || 0,
        is_authenticated_endpoint: features.is_authenticated_endpoint || 0,
        label: v.userLabel === 'real' ? 1 : 0
      };
    });

    res.json(formatted);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

router.use(authMiddleware);

// GET /api/scans — list all scans for the logged-in user (with repo info)
router.get('/', async (req, res) => {
  try {
    const scans = await prisma.scan.findMany({
      where: { userId: req.userId },
      include: {
        repository: { select: { name: true, fullName: true, platform: true } },
        _count: { select: { vulnerabilities: true } },
      },
      orderBy: { createdAt: 'desc' },
      take: 20,
    });
    res.json(scans);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/scans/:id — single scan with all its vulnerabilities
router.get('/:id', async (req, res) => {
  try {
    const scan = await prisma.scan.findFirst({
      where: { id: parseInt(req.params.id), userId: req.userId },
      include: {
        repository: true,
        vulnerabilities: { orderBy: [{ severity: 'asc' }, { createdAt: 'desc' }] },
      },
    });
    if (!scan) return res.status(404).json({ message: 'Scan not found' });
    res.json(scan);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/scans/trigger — trigger a real SAST/Secret scan for a repo
router.post('/trigger', async (req, res) => {
  const { repositoryId } = req.body;
  if (!repositoryId) return res.status(400).json({ message: 'repositoryId is required' });

  try {
    // Verify the repo belongs to this user
    const repo = await prisma.repository.findFirst({
      where: { id: parseInt(repositoryId), userId: req.userId },
    });
    if (!repo) return res.status(404).json({ message: 'Repository not found' });

    // Path to scan is the project root folder (one directory up from backend)
    const scanPath = path.join(__dirname, '..', '..');
    
    // Execute real security scan
    const scanResult = runSecurityScan(scanPath);

    // Fetch historical tracking metrics from DB to append to ML Features
    for (let finding of scanResult.findings) {
      if (finding.mlFeatures) {
        // Count how many times this specific rule + file was seen before
        const seenCount = await prisma.vulnerability.count({
          where: {
            ruleId: finding.ruleId,
            filePath: finding.filePath,
            scan: { repositoryId: repo.id }
          }
        });
        finding.mlFeatures.same_finding_seen_before_count = seenCount;

        // Count how many times a similar finding was dismissed
        const dismissedCount = await prisma.vulnerability.count({
          where: {
            ruleId: finding.ruleId,
            status: 'ignored',
            scan: { repositoryId: repo.id }
          }
        });
        finding.mlFeatures.developer_dismissed_similar_before = dismissedCount;
        finding.mlFeatures.file_change_frequency = 0; // Fallback limitation

        // Map internal ruleIds to trained classifier categories
        const RULE_MAP = {
          'SAST-001': 'sqli-concat',
          'SAST-002': 'xss-unescaped',
          'SAST-003': 'path-traversal',
          'SAST-004': 'hardcoded-secret',
          'SAST-005': 'insecure-deserialize',
          'SEC-001': 'hardcoded-secret',
          'SEC-002': 'hardcoded-secret',
          'SEC-003': 'hardcoded-secret',
        };
        finding.mlFeatures.rule_id = RULE_MAP[finding.ruleId] || finding.ruleId;
        finding.mlFeatures.cwe_id = finding.cweId;
      }
    }

    // Filter Findings via ML Classifier
    let finalFindings = scanResult.findings;
    const sastFindings = scanResult.findings.filter(f => f.mlFeatures);
    
    if (sastFindings.length > 0) {
      const BATCH_SIZE = 50;
      const results = [];
      const CLASSIFIER_URL = process.env.FP_CLASSIFIER_URL || "http://localhost:8001";
      const headers = { 'Content-Type': 'application/json' };
      if (process.env.CLASSIFIER_API_KEY) {
        headers['X-SecureGuard-Key'] = process.env.CLASSIFIER_API_KEY;
      }

      for (let i = 0; i < sastFindings.length; i += BATCH_SIZE) {
        const chunk = sastFindings.slice(i, i + BATCH_SIZE);
        const payload = { findings: chunk.map(f => f.mlFeatures) };
        
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        try {
          const response = await fetch(`${CLASSIFIER_URL}/classify/batch`, {
            method: 'POST',
            headers,
            body: JSON.stringify(payload),
            signal: controller.signal
          });
          clearTimeout(timeoutId);

          if (response.ok) {
            const data = await response.json();
            results.push(...(data.results || []));
          } else {
            console.warn(`[ML Service Error] Classifier returned status ${response.status} for chunk. Failing open.`);
            results.push(...Array(chunk.length).fill(null));
          }
        } catch (err) {
          clearTimeout(timeoutId);
          console.warn(`[ML Service Error] Failed to reach FP classifier for chunk. Error: ${err.message}. Failing open.`);
          results.push(...Array(chunk.length).fill(null));
        }
      }

      // Keep all findings but assign status based on ML prediction
      const processedSastFindings = sastFindings.map((f, idx) => {
        const res = results[idx];
        const pred = res?.prediction || 'REAL'; // Fail-open to REAL
        const explanations = res?.explanations || [];

        return {
          ...f,
          status: pred === 'FALSE_POSITIVE' ? 'ignored' : 'open',
          mlFeatures: {
            ...f.mlFeatures,
            ml_prediction: pred,
            ml_confidence: res ? res.confidence : 1.0,
            ml_explanation: explanations
          }
        };
      });

      // Combine processed SAST findings with non-SAST (e.g. dependency, secrets)
      finalFindings = [
        ...scanResult.findings.filter(f => !f.mlFeatures).map(f => ({ ...f, status: 'open' })),
        ...processedSastFindings
      ];
    }

    // Group findings count by severity (only count active 'open' findings)
    const critCount = finalFindings.filter(f => f.status === 'open' && f.severity === 'critical').length;
    const highCount = finalFindings.filter(f => f.status === 'open' && f.severity === 'high').length;
    const medCount  = finalFindings.filter(f => f.status === 'open' && f.severity === 'medium').length;
    const lowCount  = finalFindings.filter(f => f.status === 'open' && f.severity === 'low').length;
    const secrets   = finalFindings.filter(f => f.status === 'open' && f.type === 'secret').length;

    // Create the scan database entry
    const scan = await prisma.scan.create({
      data: {
        userId: req.userId,
        repositoryId: repo.id,
        status: 'completed',
        branch: 'main',
        totalFiles: scanResult.totalFiles,
        totalLines: scanResult.totalLines,
        criticalCount: critCount,
        highCount: highCount,
        mediumCount: medCount,
        lowCount: lowCount,
        secretsFound: secrets,
        durationMs: scanResult.durationMs,
        completedAt: new Date(),
      },
    });

    // Save final findings as vulnerabilities
    if (finalFindings.length > 0) {
      const dbFindings = finalFindings.map(f => ({
        scanId: scan.id,
        ruleId: f.ruleId,
        cweId: f.cweId,
        type: f.type,
        severity: f.severity,
        title: f.title,
        filePath: f.filePath,
        lineStart: f.lineStart,
        lineEnd: f.lineEnd,
        codeSnippet: f.codeSnippet,
        status: 'open',
        mlFeatures: f.mlFeatures ? f.mlFeatures : null
      }));
      await prisma.vulnerability.createMany({ data: dbFindings });
    }

    // Update repo risk level based on scan results
    const riskLevel = critCount > 0 ? 'critical' : highCount > 2 ? 'high' : medCount > 3 ? 'medium' : 'low';
    await prisma.repository.update({
      where: { id: repo.id },
      data: { riskLevel, updatedAt: new Date() },
    });

    res.status(201).json({ scan, message: `Scan completed. Evaluated ${scanResult.totalFiles} files. Found ${finalFindings.length} real issues.` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/scans/stats/summary — dashboard summary stats for this user
router.get('/stats/summary', async (req, res) => {
  try {
    const vulns = await prisma.vulnerability.findMany({
      where: {
        scan: { userId: req.userId },
        status: 'open',
      },
      select: { severity: true },
    });

    const critical = vulns.filter(v => v.severity === 'critical').length;
    const high     = vulns.filter(v => v.severity === 'high').length;
    const medium   = vulns.filter(v => v.severity === 'medium').length;
    const low      = vulns.filter(v => v.severity === 'low').length;
    const total    = vulns.length;
    const health   = Math.max(0, 100 - critical * 15 - high * 8 - medium * 3 - low);

    const lastScan = await prisma.scan.findFirst({
      where: { userId: req.userId, status: 'completed' },
      orderBy: { createdAt: 'desc' },
      select: { durationMs: true, totalFiles: true, createdAt: true },
    });

    res.json({ critical, high, medium, low, total, health, lastScan });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
