const express = require('express');
const router = express.Router();
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { runSecurityScan } = require('../utils/securityScanner');
const path = require('path');

// Webhook endpoint does NOT require auth header since it's called by Github/Gitlab
router.post('/webhook/:platform', async (req, res) => {
  const { platform } = req.params;
  const payload = req.body;
  
  console.log(`[Webhook Received] Platform: ${platform}`);
  
  try {
    let repoFullName = '';
    let commitSha = '';
    let branch = 'main';

    if (platform === 'github') {
      repoFullName = payload.repository?.full_name || '';
      commitSha = payload.head_commit?.id || payload.after || '';
      branch = payload.ref ? payload.ref.replace('refs/heads/', '') : 'main';
    } else if (platform === 'gitlab') {
      repoFullName = payload.project?.path_with_namespace || '';
      commitSha = payload.checkout_sha || '';
      branch = payload.ref ? payload.ref.replace('refs/heads/', '') : 'main';
    }

    if (!repoFullName) {
      return res.status(400).json({ message: 'Could not extract repository full name from payload' });
    }

    // Find the repository and user in database
    const repo = await prisma.repository.findFirst({
      where: { fullName: repoFullName, platform },
    });

    if (!repo) {
      return res.status(404).json({ message: `Repository ${repoFullName} is not registered in SecureGuard` });
    }

    // Trigger scanning of the repository
    const scanPath = path.join(__dirname, '..', '..'); // scan parent directory locally
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

        // Fill required IDs
        finding.mlFeatures.rule_id = finding.ruleId;
        finding.mlFeatures.cwe_id = finding.cweId;
      }
    }

    // Filter Findings via ML Classifier
    let finalFindings = scanResult.findings;
    const sastFindings = scanResult.findings.filter(f => f.mlFeatures);
    
    if (sastFindings.length > 0) {
      try {
        const payload = { findings: sastFindings.map(f => f.mlFeatures) };
        const CLASSIFIER_URL = process.env.FP_CLASSIFIER_URL || "http://localhost:8001";
        
        const response = await fetch(`${CLASSIFIER_URL}/classify/batch`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        if (response.ok) {
          const { results } = await response.json();
          const realSastFindings = sastFindings.filter((_, idx) => {
            const pred = results[idx]?.prediction;
            return pred === 'REAL' || !pred;
          });
          
          finalFindings = [
            ...scanResult.findings.filter(f => !f.mlFeatures),
            ...realSastFindings
          ];
        } else {
          console.warn(`[ML Service Error] Classifier returned status ${response.status}. Defaulting all findings to REAL.`);
        }
      } catch (err) {
        console.warn(`[ML Service Error] Failed to reach FP classifier at ${process.env.FP_CLASSIFIER_URL}. Fallback: keeping all findings. Error: ${err.message}`);
      }
    }

    const critCount = finalFindings.filter(f => f.severity === 'critical').length;
    const highCount = finalFindings.filter(f => f.severity === 'high').length;
    const medCount  = finalFindings.filter(f => f.severity === 'medium').length;
    const lowCount  = finalFindings.filter(f => f.severity === 'low').length;
    const secrets   = finalFindings.filter(f => f.type === 'secret').length;

    // Create the scan entry in the DB
    const scan = await prisma.scan.create({
      data: {
        userId: repo.userId,
        repositoryId: repo.id,
        status: 'completed',
        branch,
        commitSha: commitSha || 'push-event',
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
        status: 'open'
      }));
      await prisma.vulnerability.createMany({ data: dbFindings });
    }

    // Update repository risk level
    const riskLevel = critCount > 0 ? 'critical' : highCount > 2 ? 'high' : medCount > 3 ? 'medium' : 'low';
    await prisma.repository.update({
      where: { id: repo.id },
      data: { riskLevel, updatedAt: new Date() },
    });

    // PR Bot check action simulation
    console.log(`[PR Bot] Scanned commit ${commitSha}. Found ${scanResult.findings.length} issues.`);

    return res.status(200).json({
      message: 'Webhook processed, scan successfully completed',
      scanId: scan.id,
      issuesFound: scanResult.findings.length
    });
  } catch (err) {
    console.error('[Webhook Error]', err);
    return res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Protect all other routes below with authentication middleware
router.use(authMiddleware);

// GET /api/integration/tokens: Check user configuration for tokens
router.get('/tokens', async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.userId },
      select: { githubToken: true, gitlabToken: true }
    });
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({
      hasGithub: !!user.githubToken,
      hasGitlab: !!user.gitlabToken
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/integration/tokens: Save personal access tokens
router.post('/tokens', async (req, res) => {
  const { githubToken, gitlabToken } = req.body;
  try {
    const data = {};
    if (githubToken !== undefined) data.githubToken = githubToken;
    if (gitlabToken !== undefined) data.gitlabToken = gitlabToken;

    await prisma.user.update({
      where: { id: req.userId },
      data
    });
    res.json({ message: 'Integration tokens successfully updated' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/integration/repos: Get active repositories from Github/Gitlab using PAT
router.get('/repos', async (req, res) => {
  const { platform } = req.query;
  if (!platform || (platform !== 'github' && platform !== 'gitlab')) {
    return res.status(400).json({ message: 'Platform must be github or gitlab' });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: req.userId },
      select: { githubToken: true, gitlabToken: true }
    });

    if (!user) return res.status(404).json({ message: 'User not found' });

    const token = platform === 'github' ? user.githubToken : user.gitlabToken;
    if (!token) {
      return res.status(200).json([]); // Return empty list if no token is configured
    }

    if (platform === 'github') {
      const response = await fetch('https://api.github.com/user/repos?per_page=50&sort=updated', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'SecureGuard-App'
        }
      });
      if (!response.ok) {
        return res.status(response.status).json({ message: 'Failed fetching repositories from GitHub API' });
      }
      const data = await response.json();
      const repos = data.map(r => ({
        name: r.name,
        fullName: r.full_name,
        url: r.html_url,
        platform: 'github',
        language: r.language || 'JavaScript'
      }));
      return res.json(repos);
    } else {
      // GitLab API
      const response = await fetch('https://gitlab.com/api/v4/projects?owned=true&per_page=50', {
        headers: {
          'PRIVATE-TOKEN': token
        }
      });
      if (!response.ok) {
        return res.status(response.status).json({ message: 'Failed fetching repositories from GitLab API' });
      }
      const data = await response.json();
      const repos = data.map(r => ({
        name: r.name,
        fullName: r.path_with_namespace,
        url: r.web_url,
        platform: 'gitlab',
        language: 'JavaScript'
      }));
      return res.json(repos);
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/integration/pr-bot: Simulate a PR Bot check response
router.post('/pr-bot', async (req, res) => {
  const { repositoryId, commitSha, prNumber } = req.body;
  if (!repositoryId || !commitSha) {
    return res.status(400).json({ message: 'repositoryId and commitSha are required' });
  }

  try {
    const repo = await prisma.repository.findFirst({
      where: { id: parseInt(repositoryId), userId: req.userId },
    });
    if (!repo) return res.status(404).json({ message: 'Repository not found' });

    // Fetch the latest scan for this commit or repo
    const scan = await prisma.scan.findFirst({
      where: { repositoryId: repo.id, userId: req.userId },
      orderBy: { createdAt: 'desc' },
      include: { vulnerabilities: true }
    });

    const isClean = !scan || (scan.criticalCount + scan.highCount === 0);

    const checkSummary = {
      repository: repo.fullName,
      commit: commitSha,
      prNumber: prNumber || 42,
      status: isClean ? 'success' : 'failure',
      conclusion: isClean ? 'SecureGuard checklist passed!' : 'Vulnerabilities detected!',
      issuesFound: scan ? scan.criticalCount + scan.highCount : 0,
      reportUrl: `http://localhost:5173/dashboard`
    };

    console.log(`[PR Bot Action Logged]`, checkSummary);

    res.json({
      message: 'PR Bot check simulated successfully',
      botReport: checkSummary
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
