/**
 * node_integration_example.js
 *
 * Aapke Express/Fastify backend me is tarah classifier service ko call karo.
 * Ye SAST scan pipeline ke baad chalega - raw findings filter karke sirf
 * REAL vulnerabilities dashboard/DB me save karega.
 */

const CLASSIFIER_SERVICE_URL = process.env.FP_CLASSIFIER_URL || "http://localhost:8001";

async function filterFalsePositives(sastFindings) {
  // sastFindings: aapke SAST engine (Semgrep) se aaye raw findings ka array
  // Har finding ko classifier ke expected format me convert karo
  const payload = {
    findings: sastFindings.map((f) => ({
      rule_id: f.ruleId,
      cwe_id: f.cweId,
      is_string_concat: f.isStringConcat ? 1 : 0,
      is_parameterized_query: f.isParameterizedQuery ? 1 : 0,
      has_sanitizer_nearby: f.hasSanitizerNearby ? 1 : 0,
      in_test_file: f.filePath.includes("/test") || f.filePath.includes(".test.") ? 1 : 0,
      is_in_vendor_or_generated_dir: f.filePath.includes("node_modules") || f.filePath.includes("/vendor/") ? 1 : 0,
      taint_source_distance: f.taintDistance ?? 5,
      function_complexity: f.cyclomaticComplexity ?? 5,
      code_snippet_length: f.codeSnippet?.length ?? 100,
      variable_name_entropy: f.variableEntropy ?? 2.5,
      is_user_input_direct: f.isDirectUserInput ? 1 : 0,
      has_type_validation: f.hasTypeValidation ? 1 : 0,
      is_third_party_lib_call: f.isThirdPartyCall ? 1 : 0,
      same_finding_seen_before_count: f.historicalCount ?? 0,
      developer_dismissed_similar_before: f.previouslyDismissed ? 1 : 0,
      file_change_frequency: f.fileChurn ?? 0,
      is_authenticated_endpoint: f.isAuthEndpoint ? 1 : 0,
    })),
  };

  const response = await fetch(`${CLASSIFIER_SERVICE_URL}/classify/batch`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(`Classifier service error: ${response.status}`);
  }

  const { results } = await response.json();

  // Sirf REAL predictions ko rakho, FALSE_POSITIVE filter kar do
  return sastFindings.filter((_, idx) => results[idx].prediction === "REAL");
}

// Usage example (aapke scan pipeline me):
// const rawFindings = await runSastScan(repoPath);
// const realVulnerabilities = await filterFalsePositives(rawFindings);
// await saveToDatabase(realVulnerabilities);

module.exports = { filterFalsePositives };
