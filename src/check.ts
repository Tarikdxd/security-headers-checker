export type Status = 'pass' | 'warn' | 'fail';

export interface CheckResult {
  id: string;
  title: string;
  status: Status;
  detail: string;
  weight: number;
}

export interface Audit {
  url: string;
  finalUrl: string;
  httpStatus: number;
  score: number;
  grade: string;
  checks: CheckResult[];
}

/** HSTS için önerilen minimum: 180 gün. */
export const RECOMMENDED_HSTS_MAX_AGE = 15_552_000;

export function headerMap(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

export function cookieIssues(cookies: string[]): string[] {
  const issues: string[] = [];
  for (const cookie of cookies) {
    const name = cookie.split('=')[0]?.trim() || 'cookie';
    if (!/;\s*secure\b/i.test(cookie)) issues.push(`${name}: Secure yok`);
    if (!/;\s*httponly\b/i.test(cookie)) issues.push(`${name}: HttpOnly yok`);
    if (!/;\s*samesite=(lax|strict|none)\b/i.test(cookie)) issues.push(`${name}: SameSite yok`);
  }
  return issues;
}

export function scoreChecks(checks: CheckResult[]): { score: number; grade: string } {
  const total = checks.reduce((sum, c) => sum + c.weight, 0);
  const earned = checks.reduce(
    (sum, c) => sum + (c.status === 'pass' ? c.weight : c.status === 'warn' ? c.weight * 0.5 : 0),
    0,
  );
  const score = total > 0 ? Math.round((earned / total) * 100) : 0;
  const grade =
    score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : score >= 50 ? 'E' : 'F';
  return { score, grade };
}

export function evaluate(
  url: string,
  finalUrl: string,
  headers: Record<string, string>,
  httpStatus: number,
  setCookies: string[] = [],
): Audit {
  const h = (name: string): string => headers[name.toLowerCase()]?.trim() ?? '';
  const checks: CheckResult[] = [];

  const https = finalUrl.startsWith('https://');
  checks.push({
    id: 'https',
    title: 'HTTPS',
    status: https ? 'pass' : 'fail',
    detail: https ? 'Bağlantı HTTPS üzerinden.' : 'Son URL HTTPS değil; tüm trafik şifrelenmeli.',
    weight: 10,
  });

  const hsts = h('strict-transport-security');
  if (!hsts) {
    checks.push({
      id: 'hsts',
      title: 'HSTS',
      status: 'fail',
      detail: 'Strict-Transport-Security başlığı yok.',
      weight: 15,
    });
  } else {
    const maxAge = Number(/max-age=(\d+)/i.exec(hsts)?.[1] ?? 0);
    const sub = /includesubdomains/i.test(hsts);
    const preload = /preload/i.test(hsts);
    const problems: string[] = [];
    if (!maxAge) problems.push('max-age eksik');
    else if (maxAge < RECOMMENDED_HSTS_MAX_AGE) {
      problems.push(`max-age kısa (${maxAge}s < ${RECOMMENDED_HSTS_MAX_AGE}s)`);
    }
    if (!sub) problems.push('includeSubDomains yok');
    checks.push({
      id: 'hsts',
      title: 'HSTS',
      status: problems.length ? 'warn' : 'pass',
      detail: problems.length
        ? problems.join(', ')
        : `max-age=${maxAge}${sub ? ', includeSubDomains' : ''}${preload ? ', preload' : ''}`,
      weight: 15,
    });
  }

  const csp = h('content-security-policy');
  if (!csp) {
    checks.push({
      id: 'csp',
      title: 'CSP',
      status: 'fail',
      detail: 'Content-Security-Policy yok.',
      weight: 15,
    });
  } else {
    const problems: string[] = [];
    if (/unsafe-inline/i.test(csp)) problems.push("'unsafe-inline'");
    if (/unsafe-eval/i.test(csp)) problems.push("'unsafe-eval'");
    if (/(^|[\s;])\*([\s;]|$)/.test(csp)) problems.push("'*' kaynağı");
    if (!/default-src/i.test(csp)) problems.push('default-src yok');
    if (!/frame-ancestors/i.test(csp)) problems.push('frame-ancestors yok');
    checks.push({
      id: 'csp',
      title: 'CSP',
      status: problems.length ? 'warn' : 'pass',
      detail: problems.length ? `Zayıf/eksik: ${problems.join(', ')}` : 'Temel CSP kuralları mevcut.',
      weight: 15,
    });
  }

  const xfo = h('x-frame-options').toLowerCase();
  const frameOk = xfo === 'deny' || xfo === 'sameorigin' || /frame-ancestors/i.test(csp);
  checks.push({
    id: 'frame',
    title: 'Clickjacking koruması',
    status: frameOk ? 'pass' : 'fail',
    detail: frameOk
      ? 'X-Frame-Options veya CSP frame-ancestors mevcut.'
      : 'X-Frame-Options/frame-ancestors yok.',
    weight: 8,
  });

  const nosniff = h('x-content-type-options').toLowerCase() === 'nosniff';
  checks.push({
    id: 'nosniff',
    title: 'MIME sniffing',
    status: nosniff ? 'pass' : 'fail',
    detail: nosniff ? 'X-Content-Type-Options: nosniff.' : 'X-Content-Type-Options: nosniff yok.',
    weight: 8,
  });

  const referrer = h('referrer-policy').toLowerCase();
  const referrerBad = !referrer || referrer === 'unsafe-url' || referrer === 'no-referrer-when-downgrade';
  checks.push({
    id: 'referrer',
    title: 'Referrer-Policy',
    status: referrerBad ? (referrer ? 'warn' : 'fail') : 'pass',
    detail: referrer ? `Değer: ${referrer}` : 'Referrer-Policy yok.',
    weight: 6,
  });

  const permissions = h('permissions-policy');
  checks.push({
    id: 'permissions',
    title: 'Permissions-Policy',
    status: permissions ? 'pass' : 'warn',
    detail: permissions ? 'Tanımlı.' : 'Tanımlı değil (önerilir).',
    weight: 6,
  });

  const coop = h('cross-origin-opener-policy');
  const coep = h('cross-origin-embedder-policy');
  const corp = h('cross-origin-resource-policy');
  checks.push({
    id: 'coop',
    title: 'Cross-Origin-Opener-Policy',
    status: coop ? 'pass' : 'warn',
    detail: coop || 'Yok (önerilir).',
    weight: 5,
  });
  checks.push({
    id: 'coep',
    title: 'Cross-Origin-Embedder-Policy',
    status: coep ? 'pass' : 'warn',
    detail: coep || 'Yok (önerilir).',
    weight: 3,
  });
  checks.push({
    id: 'corp',
    title: 'Cross-Origin-Resource-Policy',
    status: corp ? 'pass' : 'warn',
    detail: corp || 'Yok (önerilir).',
    weight: 3,
  });

  const server = h('server');
  const powered = h('x-powered-by');
  checks.push({
    id: 'disclosure',
    title: 'Sürüm/teknoloji ifşası',
    status: server || powered ? 'warn' : 'pass',
    detail:
      server || powered
        ? `Açık başlık: ${[server && `Server: ${server}`, powered && `X-Powered-By: ${powered}`]
            .filter(Boolean)
            .join(', ')}`
        : 'Sunucu/teknoloji başlığı yok.',
    weight: 4,
  });

  const acao = h('access-control-allow-origin');
  const acac = h('access-control-allow-credentials').toLowerCase() === 'true';
  if (acao === '*' && acac) {
    checks.push({
      id: 'cors',
      title: 'CORS',
      status: 'fail',
      detail: 'Wildcard origin + credentials birlikte kullanılamaz.',
      weight: 6,
    });
  } else if (acao === '*') {
    checks.push({
      id: 'cors',
      title: 'CORS',
      status: 'warn',
      detail: 'Wildcard origin; herkes okuyabilir.',
      weight: 6,
    });
  } else {
    checks.push({
      id: 'cors',
      title: 'CORS',
      status: 'pass',
      detail: acao ? `Origin: ${acao}` : 'Kısıtlı/varsayılan.',
      weight: 6,
    });
  }

  const cookieProblems = cookieIssues(setCookies);
  checks.push({
    id: 'cookies',
    title: 'Çerez bayrakları',
    status: cookieProblems.length ? 'warn' : 'pass',
    detail: cookieProblems.length ? cookieProblems.join(', ') : 'Set-Cookie yok veya bayraklar tam.',
    weight: 8,
  });

  const { score, grade } = scoreChecks(checks);
  return { url, finalUrl, httpStatus, score, grade, checks };
}
