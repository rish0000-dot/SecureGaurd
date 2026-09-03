/**
 * SPDX 2.3 JSON Document Validator
 * 
 * Validates generated SPDX documents against required metadata specifications,
 * unique identifier rules, and Package URL (PURL) standards.
 */

function validateSpdxDocument(doc) {
  const errors = [];

  if (!doc || typeof doc !== 'object') {
    return { isValid: false, errors: ['Document is empty or not an object'] };
  }

  // 1. Mandatory Top-Level Fields
  if (doc.spdxVersion !== 'SPDX-2.3') {
    errors.push(`Invalid or missing spdxVersion: expected "SPDX-2.3", received "${doc.spdxVersion}"`);
  }
  if (doc.dataLicense !== 'CC0-1.0') {
    errors.push(`Invalid or missing dataLicense: expected "CC0-1.0", received "${doc.dataLicense}"`);
  }
  if (doc.SPDXID !== 'SPDXRef-DOCUMENT') {
    errors.push(`Invalid or missing SPDXID: expected "SPDXRef-DOCUMENT", received "${doc.SPDXID}"`);
  }
  if (!doc.name || typeof doc.name !== 'string') {
    errors.push('Missing or invalid document name');
  }
  if (!doc.documentNamespace || !doc.documentNamespace.startsWith('http')) {
    errors.push(`Invalid documentNamespace URI: "${doc.documentNamespace}"`);
  }

  // 2. Creation Info Validation
  if (!doc.creationInfo || typeof doc.creationInfo !== 'object') {
    errors.push('Missing creationInfo metadata object');
  } else {
    if (!Array.isArray(doc.creationInfo.creators) || doc.creationInfo.creators.length === 0) {
      errors.push('creationInfo.creators must be a non-empty array');
    }
    if (!doc.creationInfo.created || isNaN(Date.parse(doc.creationInfo.created))) {
      errors.push(`Invalid created timestamp: "${doc.creationInfo?.created}"`);
    }
  }

  // 3. Packages Validation
  if (!Array.isArray(doc.packages)) {
    errors.push('packages field must be an array');
  } else {
    const seenSpdxIds = new Set();

    doc.packages.forEach((pkg, index) => {
      if (!pkg.SPDXID || typeof pkg.SPDXID !== 'string') {
        errors.push(`Package at index ${index} is missing SPDXID`);
      } else {
        if (seenSpdxIds.has(pkg.SPDXID)) {
          errors.push(`Duplicate SPDXID detected in package list: "${pkg.SPDXID}"`);
        }
        seenSpdxIds.add(pkg.SPDXID);
      }

      if (!pkg.name || typeof pkg.name !== 'string') {
        errors.push(`Package at index ${index} is missing name`);
      }
      if (pkg.filesAnalyzed !== false && pkg.filesAnalyzed !== true) {
        errors.push(`Package "${pkg.name}" is missing boolean filesAnalyzed flag`);
      }

      // External Refs PURL Check
      if (pkg.externalRefs && Array.isArray(pkg.externalRefs)) {
        pkg.externalRefs.forEach((ref, refIdx) => {
          if (ref.referenceType === 'purl') {
            if (!ref.referenceLocator || !ref.referenceLocator.startsWith('pkg:')) {
              errors.push(`Package "${pkg.name}" has invalid PURL at externalRef ${refIdx}: "${ref.referenceLocator}"`);
            }
          }
        });
      }
    });
  }

  // 4. Relationships Validation
  if (doc.relationships && !Array.isArray(doc.relationships)) {
    errors.push('relationships field must be an array when present');
  }

  return {
    isValid: errors.length === 0,
    errors
  };
}

module.exports = {
  validateSpdxDocument
};
