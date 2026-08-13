const fs = require('fs');
const path = require('path');
const prisma = require('../prismaClient');
const { runSecurityScan } = require('../utils/securityScanner');

async function generateReport() {
  const scanPath = path.join(__dirname, 'fixtures');
  const scanResult = runSecurityScan(scanPath);
  
  // Build features
  for (let finding of scanResult.findings) {
    if (finding.mlFeatures) {
      finding.mlFeatures.same_finding_seen_before_count = await prisma.vulnerability.count({
        where: { ruleId: finding.ruleId, filePath: finding.filePath }
      });
      finding.mlFeatures.developer_dismissed_similar_before = await prisma.vulnerability.count({
        where: { ruleId: finding.ruleId, status: 'ignored' }
      });
      finding.mlFeatures.file_change_frequency = 0;
      const RULE_MAP = {
        'SAST-001': 'sqli-concat', 'SAST-002': 'xss-unescaped',
        'SAST-003': 'path-traversal', 'SAST-004': 'hardcoded-secret',
        'SAST-005': 'insecure-deserialize',
        'SEC-001': 'hardcoded-secret', 'SEC-002': 'hardcoded-secret', 'SEC-003': 'hardcoded-secret',
      };
      finding.mlFeatures.rule_id = RULE_MAP[finding.ruleId] || finding.ruleId;
      finding.mlFeatures.cwe_id = finding.cweId;
    }
  }

  const sastFindings = scanResult.findings.filter(f => f.mlFeatures);
  const CLASSIFIER_URL = process.env.FP_CLASSIFIER_URL || "http://localhost:8001";
  
  let results = [];
  try {
    const payload = { findings: sastFindings.map(f => f.mlFeatures) };
    const response = await fetch(`${CLASSIFIER_URL}/classify/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (response.ok) {
      const data = await response.json();
      results = data.results;
    }
  } catch (e) {
    console.error("Classifier fetch failed:", e.message);
  }

  let md = `# SAST Findings Features & Predictions Report\n\n`;
  md += `This report details the static analysis features and machine learning classifier predictions for all **${sastFindings.length} findings** detected in the test fixtures folder.\n\n`;

  sastFindings.forEach((f, idx) => {
    const res = results[idx] || { prediction: "ERROR", confidence: 0.0, threshold_used: 0.4 };
    const fileLoc = `${path.basename(f.filePath)}:${f.lineStart}`;
    const feat = f.mlFeatures;

    md += `## Finding ${idx + 1}: \`${fileLoc}\`\n`;
    md += `* **Rule ID:** \`${f.ruleId}\`\n`;
    md += `* **CWE:** \`${f.cweId}\`\n`;
    md += `* **Snippet:** \`${f.codeSnippet}\`\n`;
    md += `* **Classifier Prediction:** **${res.prediction}** (Confidence: \`${res.confidence}\`, Threshold: \`${res.threshold_used}\`)\n\n`;

    md += `### 18 Feature Input Values\n\n`;
    md += `| Feature Name | Value | Feature Name | Value |\n`;
    md += `| :--- | :--- | :--- | :--- |\n`;
    md += `| **rule_id** | \`${feat.rule_id}\` | **cwe_id** | \`${feat.cwe_id}\` |\n`;
    md += `| **is_string_concat** | \`${feat.is_string_concat}\` | **is_parameterized_query** | \`${feat.is_parameterized_query}\` |\n`;
    md += `| **has_sanitizer_nearby** | \`${feat.has_sanitizer_nearby}\` | **in_test_file** | \`${feat.in_test_file}\` |\n`;
    md += `| **is_in_vendor_or_generated_dir** | \`${feat.is_in_vendor_or_generated_dir}\` | **taint_source_distance** | \`${feat.taint_source_distance}\` |\n`;
    md += `| **function_complexity** | \`${feat.function_complexity}\` | **code_snippet_length** | \`${feat.code_snippet_length}\` |\n`;
    md += `| **variable_name_entropy** | \`${feat.variable_name_entropy}\` | **is_user_input_direct** | \`${feat.is_user_input_direct}\` |\n`;
    md += `| **has_type_validation** | \`${feat.has_type_validation}\` | **is_third_party_lib_call** | \`${feat.is_third_party_lib_call}\` |\n`;
    md += `| **same_finding_seen_before_count** | \`${feat.same_finding_seen_before_count}\` | **developer_dismissed_similar_before** | \`${feat.developer_dismissed_similar_before}\` |\n`;
    md += `| **file_change_frequency** | \`${feat.file_change_frequency}\` | **is_authenticated_endpoint** | \`${feat.is_authenticated_endpoint}\` |\n\n`;
    md += `---\n\n`;
  });

  const reportPath = path.join('C:', 'Users', 'Rishabh Sharma', '.gemini', 'antigravity', 'brain', 'd8391f48-5653-404a-bc5c-ea72b02020dd', 'sast_findings_report.md');
  fs.writeFileSync(reportPath, md);
  console.log(`Report generated successfully at: ${reportPath}`);
}

generateReport();
