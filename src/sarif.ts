import type { Audit, CheckResult } from './check.ts';

interface RuleInfo {
  name: string;
  helpUri: string;
}

const RULES: Record<string, RuleInfo> = {
  https: {
    name: 'HTTPS',
    helpUri:
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security',
  },
  hsts: {
    name: 'Strict-Transport-Security',
    helpUri:
      'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html',
  },
  csp: {
    name: 'Content-Security-Policy',
    helpUri:
      'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html',
  },
  frame: {
    name: 'Clickjacking protection',
    helpUri:
      'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html',
  },
  nosniff: {
    name: 'X-Content-Type-Options',
    helpUri:
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/02-Testing_for_JavaScript_Execution',
  },
  referrer: {
    name: 'Referrer-Policy',
    helpUri:
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema',
  },
  permissions: {
    name: 'Permissions-Policy',
    helpUri: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy',
  },
  coop: {
    name: 'Cross-Origin-Opener-Policy',
    helpUri: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy',
  },
  coep: {
    name: 'Cross-Origin-Embedder-Policy',
    helpUri:
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy',
  },
  corp: {
    name: 'Cross-Origin-Resource-Policy',
    helpUri:
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy',
  },
  disclosure: {
    name: 'Technology disclosure',
    helpUri:
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server',
  },
  cors: {
    name: 'Cross-Origin Resource Sharing',
    helpUri:
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Site_Scripting',
  },
  cookies: {
    name: 'Cookie flags',
    helpUri:
      'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
  },
};

const DEFAULT_HELP_URI =
  'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/';

function ruleFor(check: CheckResult) {
  const info = RULES[check.id];
  return {
    id: check.id,
    name: info?.name ?? check.title,
    shortDescription: { text: check.title },
    helpUri: info?.helpUri ?? DEFAULT_HELP_URI,
    properties: { tags: ['security', 'http-headers'] },
  };
}

/**
 * Render an audit as SARIF 2.1.0 so GitHub Code Scanning and other consumers can
 * annotate pull requests with failed or weak HTTP security headers.
 */
export function toSarif(audit: Audit): Record<string, unknown> {
  const rules = audit.checks.map(ruleFor);
  const results = audit.checks
    .filter((check) => check.status !== 'pass')
    .map((check) => ({
      ruleId: check.id,
      level: check.status === 'fail' ? 'error' : 'warning',
      message: { text: check.detail },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: audit.finalUrl },
          },
        },
      ],
      properties: {
        'security-severity': check.status === 'fail' ? '7.5' : '4.0',
      },
    }));

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'security-headers-checker',
            informationUri:
              'https://github.com/Tarikdxd/security-headers-checker',
            version: '0.3.0',
            rules,
          },
        },
        results,
      },
    ],
  };
}
