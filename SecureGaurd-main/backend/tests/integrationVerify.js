const path = require('path');
const fs = require('fs');
const prisma = require('../prismaClient');
const { runSecurityScan } = require('../utils/securityScanner');

async function verify() {
  const targetArg = process.argv[2];
  const scanPath = targetArg ? path.resolve(targetArg) : path.join(__dirname, 'fixtures');

  console.log("=========================================");
  console.log(`Running E2E Scan on: ${scanPath}`);
  console.log("=========================================\n");

  if (!fs.existsSync(scanPath)) {
    console.error(`Error: Path does not exist: ${scanPath}`);
    process.exit(1);
  }

  const scanResult = runSecurityScan(scanPath);
  console.log(`[Scanner] Evaluated files. Found raw findings: ${scanResult.findings.length}\n`);

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
  const nonSastFindings = scanResult.findings.filter(f => !f.mlFeatures);

  if (sastFindings.length > 0) {
    const CLASSIFIER_URL = process.env.FP_CLASSIFIER_URL || "http://localhost:8001";
    try {
      const payload = { findings: sastFindings.map(f => f.mlFeatures) };
      
      const response = await fetch(`${CLASSIFIER_URL}/classify/batch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      
      if (response.ok) {
        const { results } = await response.json();
        
        // Detailed Print for each finding
        sastFindings.forEach((f, idx) => {
          const res = results[idx];
          console.log("--------------------------------------------------------------------------------");
          console.log(`[Finding ${idx + 1}] File: ${f.filePath}:${f.lineStart} | Rule: ${f.ruleId} | CWE: ${f.cweId}`);
          console.log(`Snippet: "${f.codeSnippet}"`);
          console.log("--------------------------------------------------------------------------------");
          console.log(`Prediction:  ${res.prediction}`);
          console.log(`Confidence:  ${res.confidence}`);
          console.log(`Threshold:   ${res.threshold_used}`);
          console.log("AST & DB Features (18 total):");
          
          const feat = f.mlFeatures;
          console.log(`  1. rule_id:                           ${feat.rule_id}`);
          console.log(`  2. cwe_id:                            ${feat.cwe_id}`);
          console.log(`  3. is_string_concat:                  ${feat.is_string_concat}`);
          console.log(`  4. is_parameterized_query:            ${feat.is_parameterized_query}`);
          console.log(`  5. has_sanitizer_nearby:              ${feat.has_sanitizer_nearby}`);
          console.log(`  6. in_test_file:                      ${feat.in_test_file}`);
          console.log(`  7. is_in_vendor_or_generated_dir:     ${feat.is_in_vendor_or_generated_dir}`);
          console.log(`  8. taint_source_distance:             ${feat.taint_source_distance}`);
          console.log(`  9. function_complexity:               ${feat.function_complexity}`);
          console.log(`  10. code_snippet_length:              ${feat.code_snippet_length}`);
          console.log(`  11. variable_name_entropy:            ${feat.variable_name_entropy}`);
          console.log(`  12. is_user_input_direct:             ${feat.is_user_input_direct}`);
          console.log(`  13. has_type_validation:              ${feat.has_type_validation}`);
          console.log(`  14. is_third_party_lib_call:          ${feat.is_third_party_lib_call}`);
          console.log(`  15. same_finding_seen_before_count:   ${feat.same_finding_seen_before_count}`);
          console.log(`  16. developer_dismissed_similar_before:${feat.developer_dismissed_similar_before}`);
          console.log(`  17. file_change_frequency:            ${feat.file_change_frequency}`);
          console.log(`  18. is_authenticated_endpoint:        ${feat.is_authenticated_endpoint}`);
          console.log("\n");
        });

        // Distribution Analysis
        console.log("=========================================");
        console.log("CONFIDENCE SCORE DISTRIBUTION ANALYSIS");
        console.log("=========================================");
        
        let dist = {
          highReal: 0,     // >= 0.9
          mediumReal: 0,   // 0.5 - 0.9
          borderline: 0,   // 0.4 - 0.5
          falsePositive: 0 // < 0.4
        };

        results.forEach(r => {
          const conf = r.confidence;
          if (conf >= 0.9) dist.highReal++;
          else if (conf >= 0.5) dist.mediumReal++;
          else if (conf >= 0.4) dist.borderline++;
          else dist.falsePositive++;
        });

        console.log(`High Confidence Real (>= 0.9):     ${dist.highReal}`);
        console.log(`Medium Confidence Real (0.5 - 0.9):   ${dist.mediumReal}`);
        console.log(`Borderline Real/FP (0.4 - 0.5):      ${dist.borderline}`);
        console.log(`False Positive (< 0.4):             ${dist.falsePositive}`);
        console.log("-----------------------------------------");
        console.log(`Total Classified Findings:          ${results.length}`);
        
        const realCount = results.filter(r => r.prediction === 'REAL').length;
        const fpCount = results.filter(r => r.prediction === 'FALSE_POSITIVE').length;
        console.log(`Summary: ${realCount} REAL, ${fpCount} FALSE_POSITIVE.`);
      } else {
        console.log("Classifier returned non-200 status:", response.status);
      }
    } catch (e) {
      console.log("Error querying classifier:", e.message);
    }
  } else {
    console.log("No SAST/Code findings detected to classify.");
  }

  if (nonSastFindings.length > 0) {
    console.log("\n=========================================");
    console.log("NON-SAST FINDINGS (Secrets / IaC)");
    console.log("=========================================");
    nonSastFindings.forEach((f, idx) => {
      console.log(`[Secret/IaC Finding ${idx + 1}] File: ${f.filePath}:${f.lineStart} | Rule: ${f.ruleId} | Type: ${f.type}`);
      console.log(`Snippet: "${f.codeSnippet}"\n`);
    });
  }

  process.exit(0);
}

verify();
