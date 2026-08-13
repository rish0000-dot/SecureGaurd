const babelParser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const fs = require('fs');
const path = require('path');

let sanitizerKeywords = ['sanitize', 'escape', 'validate'];
try {
  const configPath = path.join(__dirname, 'sanitizerPatterns.json');
  if (fs.existsSync(configPath)) {
    sanitizerKeywords = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  }
} catch (e) {
  // Safe fallback
}

function calculateShannonEntropy(str) {
  if (!str) return 0;
  const len = str.length;
  const frequencies = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  return Object.values(frequencies).reduce((sum, count) => {
    const p = count / len;
    return sum - p * Math.log2(p);
  }, 0);
}

function extractASTFeatures(code, filePath, ruleId, targetLine) {
  let features = {
    is_string_concat: 0,
    is_parameterized_query: 0,
    has_sanitizer_nearby: 0,
    taint_source_distance: 5, // Default baseline
    function_complexity: 1,
    code_snippet_length: 0,
    variable_name_entropy: 0,
    is_user_input_direct: 0,
    has_type_validation: 0,
    is_third_party_lib_call: 0,
    is_authenticated_endpoint: 0,
    in_test_file: filePath.includes('/test') || filePath.includes('.test.') || filePath.includes('.spec.') ? 1 : 0,
    is_in_vendor_or_generated_dir: filePath.includes('node_modules') || filePath.includes('/vendor/') || filePath.includes('/dist/') ? 1 : 0,
  };

  try {
    const ast = babelParser.parse(code, {
      sourceType: 'unambiguous',
      plugins: ['jsx', 'typescript'],
      errorRecovery: true,
    });

    const lines = code.split('\n');
    if (targetLine && targetLine <= lines.length) {
      features.code_snippet_length = lines[targetLine - 1].trim().length;
    } else {
      features.code_snippet_length = code.length;
    }

    // Find the enclosing function node that covers targetLine
    let enclosingFunctionNode = null;
    traverse(ast, {
      Function(path) {
        const { node } = path;
        if (node.loc && node.loc.start.line <= targetLine && node.loc.end.line >= targetLine) {
          if (!enclosingFunctionNode || (node.loc.end.line - node.loc.start.line < enclosingFunctionNode.loc.end.line - enclosingFunctionNode.loc.start.line)) {
            enclosingFunctionNode = node;
          }
        }
      }
    });

    // Helper to check if we are inside the target scope
    const isInsideTargetScope = (node) => {
      if (!node || !node.loc) return false;
      if (!enclosingFunctionNode) return true; // Top-level file is our scope
      return (
        node.loc.start.line >= enclosingFunctionNode.loc.start.line &&
        node.loc.end.line <= enclosingFunctionNode.loc.end.line
      );
    };

    // Helper to check if a node is on the target line
    const isTargetLineNode = (node) => {
      if (!node || !node.loc || !targetLine) return false;
      return node.loc.start.line <= targetLine && node.loc.end.line >= targetLine;
    };

    // Helper to check if a node matches user input sources
    const isUserInputSource = (node) => {
      if (!node) return false;
      if (node.type === 'MemberExpression') {
        const obj = node.object;
        const prop = node.property;
        if (obj.type === 'Identifier' && obj.name === 'req') {
          if (prop.type === 'Identifier' && ['body', 'query', 'params', 'headers'].includes(prop.name)) {
            return true;
          }
        }
        return isUserInputSource(obj);
      }
      return false;
    };

    // Helper to extract identifiers from an expression to check variables
    const getUsedIdentifiers = (node, idents = []) => {
      if (!node) return idents;
      if (node.type === 'Identifier') {
        idents.push(node.name);
      } else if (node.type === 'MemberExpression') {
        getUsedIdentifiers(node.object, idents);
      } else if (node.type === 'BinaryExpression') {
        getUsedIdentifiers(node.left, idents);
        getUsedIdentifiers(node.right, idents);
      } else if (node.type === 'TemplateLiteral') {
        node.expressions.forEach(exp => getUsedIdentifiers(exp, idents));
      } else if (node.type === 'CallExpression') {
        getUsedIdentifiers(node.callee, idents);
        node.arguments.forEach(arg => getUsedIdentifiers(arg, idents));
      }
      return idents;
    };

    let totalEntropy = 0;
    let varCount = 0;
    let imports = new Set();
    let taintDistances = {}; // map of variableName -> distance

    // Scan imports and require calls at file level
    traverse(ast, {
      ImportDeclaration(path) {
        imports.add(path.node.source.value);
        path.node.specifiers.forEach(spec => {
          imports.add(spec.local.name);
        });
      },
      CallExpression(path) {
        if (path.node.callee.name === 'require' && path.node.arguments.length > 0) {
          const arg = path.node.arguments[0];
          if (arg.type === 'StringLiteral') {
            imports.add(arg.value);
          }
        }
      }
    });

    // Main traversal
    traverse(ast, {
      VariableDeclarator(path) {
        const { node } = path;
        if (!isInsideTargetScope(node)) return;

        const { id, init } = node;
        if (id.type === 'Identifier') {
          totalEntropy += calculateShannonEntropy(id.name);
          varCount++;

          if (init) {
            if (isUserInputSource(init)) {
              taintDistances[id.name] = 1;
            } else {
              const usedVars = getUsedIdentifiers(init);
              let minParentDist = Infinity;
              for (const uv of usedVars) {
                if (taintDistances[uv] !== undefined) {
                  minParentDist = Math.min(minParentDist, taintDistances[uv]);
                }
              }
              if (minParentDist !== Infinity) {
                taintDistances[id.name] = minParentDist + 1;
              }
            }
          }
        }
      },
      AssignmentExpression(path) {
        const { node } = path;
        if (!isInsideTargetScope(node)) return;

        const { left, right } = node;
        if (left.type === 'Identifier') {
          if (isUserInputSource(right)) {
            taintDistances[left.name] = 1;
          } else {
            const usedVars = getUsedIdentifiers(right);
            let minParentDist = Infinity;
            for (const uv of usedVars) {
              if (taintDistances[uv] !== undefined) {
                minParentDist = Math.min(minParentDist, taintDistances[uv]);
              }
            }
            if (minParentDist !== Infinity) {
              taintDistances[left.name] = minParentDist + 1;
            }
          }
        }
      },
      CallExpression(path) {
        const { node } = path;
        const callee = node.callee;

        // Scope validation/authentication check
        if (isInsideTargetScope(node)) {
          if (
            (callee.type === 'MemberExpression' && callee.object.name && ['joi', 'zod', 'yup'].includes(callee.object.name.toLowerCase())) ||
            (callee.type === 'MemberExpression' && callee.property.name && ['parse', 'validate', 'safeParse'].includes(callee.property.name))
          ) {
            features.has_type_validation = 1;
          }

          if (callee.name && sanitizerKeywords.some(s => callee.name.toLowerCase().includes(s))) {
            features.has_sanitizer_nearby = 1;
          }
          if (callee.type === 'MemberExpression' && callee.property.name && sanitizerKeywords.some(s => callee.property.name.toLowerCase().includes(s))) {
            features.has_sanitizer_nearby = 1;
          }

          if (callee.name && ['requireAuth', 'isAuthenticated'].includes(callee.name)) {
            features.is_authenticated_endpoint = 1;
          }
        }

        // Target line checks
        if (isTargetLineNode(node)) {
          // is_third_party_lib_call
          if (callee.type === 'Identifier' && imports.has(callee.name)) {
            features.is_third_party_lib_call = 1;
          } else if (callee.type === 'MemberExpression' && callee.object.type === 'Identifier' && imports.has(callee.object.name)) {
            features.is_third_party_lib_call = 1;
          }

          // is_parameterized_query for SQLi
          if (ruleId === 'SAST-001') {
            const args = node.arguments;
            const hasPlaceholder = (argNode) => {
              return (argNode.type === 'StringLiteral' && (argNode.value.includes('?') || argNode.value.match(/\$\d/))) ||
                     (argNode.type === 'TemplateLiteral' && argNode.quasis.some(q => q.value.raw.includes('?') || q.value.raw.match(/\$\d/)));
            };
            if (args.some(hasPlaceholder)) {
              features.is_parameterized_query = 1;
            }
          }
        }
      },
      BinaryExpression(path) {
        const { node } = path;
        if (isTargetLineNode(node)) {
          if (node.operator === '+') {
            const hasString = node.left.type === 'StringLiteral' || node.right.type === 'StringLiteral' ||
                              node.left.type === 'TemplateLiteral' || node.right.type === 'TemplateLiteral';
            if (hasString) {
              features.is_string_concat = 1;
            }
          }
        }
      },
      StringLiteral(path) {
        const { node } = path;
        if (isTargetLineNode(node) && ruleId.startsWith('SEC-')) {
          const val = node.value;
          const entropy = calculateShannonEntropy(val);
          features.variable_name_entropy = Number(entropy.toFixed(2));
        }
      },
      TemplateLiteral(path) {
        const { node } = path;
        if (isTargetLineNode(node)) {
          if (node.expressions.length > 0) {
            features.is_string_concat = 1;
          }
          if (ruleId.startsWith('SEC-')) {
            const val = node.quasis.map(q => q.value.raw).join('');
            const entropy = calculateShannonEntropy(val);
            features.variable_name_entropy = Number(entropy.toFixed(2));
          }
        }
      },
      MemberExpression(path) {
        const { node } = path;
        if (isTargetLineNode(node)) {
          if (isUserInputSource(node)) {
            features.is_user_input_direct = 1;
            features.taint_source_distance = 1;
          }
        }
      },
      Identifier(path) {
        const { node } = path;
        if (isTargetLineNode(node)) {
          const varName = node.name;
          if (taintDistances[varName] !== undefined) {
            features.taint_source_distance = Math.min(features.taint_source_distance, taintDistances[varName]);
            if (features.taint_source_distance === 1) {
              features.is_user_input_direct = 1;
            }
          }
        }
      },
      // Complexity counters inside target scope
      IfStatement(path) { if (isInsideTargetScope(path.node)) features.function_complexity++; },
      ForStatement(path) { if (isInsideTargetScope(path.node)) features.function_complexity++; },
      WhileStatement(path) { if (isInsideTargetScope(path.node)) features.function_complexity++; },
      DoWhileStatement(path) { if (isInsideTargetScope(path.node)) features.function_complexity++; },
      SwitchCase(path) { if (isInsideTargetScope(path.node)) features.function_complexity++; },
      CatchClause(path) { if (isInsideTargetScope(path.node)) features.function_complexity++; },
      LogicalExpression(path) {
        if (isInsideTargetScope(path.node) && (path.node.operator === '&&' || path.node.operator === '||')) {
          features.function_complexity++;
        }
      }
    });

    // For secret rules, entropy was already set from the literal VALUE on the target line.
    // Do NOT overwrite it with the variable-name average, which would be much lower.
    if (varCount > 0 && !ruleId.startsWith('SEC-')) {
      features.variable_name_entropy = Number((totalEntropy / varCount).toFixed(2));
    }

  } catch (error) {
    console.warn(`[AST Parse Warning] File: ${filePath} - ${error.message}`);
  }

  return features;
}

module.exports = { extractASTFeatures };
