// Variant 1: Real aws-like key
const aws_key = 'AKIA1234567890ABCDEF'; // triggers SEC-001

// Variant 2: Private key block
const pkey = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQE\n-----END RSA PRIVATE KEY-----'; // triggers SEC-002

// Variant 3: Hardcoded config secret password
const password = 'superSecretProductionPassword123!'; // triggers SEC-003

// Variant 4: False-positive-like placeholder config (non-vulnerable)
const secretKey = 'placeholder_for_local_dev'; // triggers SEC-003 but confidence should be low