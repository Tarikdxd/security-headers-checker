import { describe, expect, it } from 'bun:test';
import { cookieIssues, evaluate, scoreChecks } from '../src/check.ts';

const secureHeaders: Record<string, string> = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'geolocation=()',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-embedder-policy': 'require-corp',
  'cross-origin-resource-policy': 'same-origin',
};

describe('evaluate', () => {
  it('tam korumalı bir yanıtı A olarak puanlar', () => {
    const audit = evaluate('https://a.test', 'https://a.test', secureHeaders, 200);
    expect(audit.score).toBeGreaterThanOrEqual(90);
    expect(audit.grade).toBe('A');
  });

  it('başlıksız bir yanıtı düşük puanlar', () => {
    const audit = evaluate('http://a.test', 'http://a.test', {}, 200);
    expect(audit.score).toBeLessThan(40);
    expect(audit.checks.find((c) => c.id === 'https')?.status).toBe('fail');
    expect(audit.checks.find((c) => c.id === 'hsts')?.status).toBe('fail');
    expect(audit.checks.find((c) => c.id === 'csp')?.status).toBe('fail');
    expect(audit.checks.find((c) => c.id === 'frame')?.status).toBe('fail');
    expect(audit.checks.find((c) => c.id === 'nosniff')?.status).toBe('fail');
  });

  it('kısa HSTS süresini uyarı olarak işaretler', () => {
    const audit = evaluate('https://a.test', 'https://a.test', {
      ...secureHeaders,
      'strict-transport-security': 'max-age=300',
    }, 200);
    expect(audit.checks.find((c) => c.id === 'hsts')?.status).toBe('warn');
  });

  it('CSP içindeki unsafe-inline değerini uyarı olarak işaretler', () => {
    const audit = evaluate('https://a.test', 'https://a.test', {
      ...secureHeaders,
      'content-security-policy': "default-src 'self'; script-src 'unsafe-inline'",
    }, 200);
    expect(audit.checks.find((c) => c.id === 'csp')?.status).toBe('warn');
  });

  it('wildcard CORS + credentials kombinasyonunu fail sayar', () => {
    const audit = evaluate('https://a.test', 'https://a.test', {
      ...secureHeaders,
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true',
    }, 200);
    expect(audit.checks.find((c) => c.id === 'cors')?.status).toBe('fail');
    expect(audit.score).toBeLessThan(100);
  });

  it('çerez bayraklarını denetler', () => {
    const audit = evaluate('https://a.test', 'https://a.test', secureHeaders, 200, [
      'session=abc; Secure; HttpOnly; SameSite=Lax',
      'tracking=1',
    ]);
    const cookies = audit.checks.find((c) => c.id === 'cookies');
    expect(cookies?.status).toBe('warn');
    expect(cookies?.detail).toContain('tracking');
    expect(cookies?.detail).toContain('Secure yok');
  });
});

describe('cookieIssues', () => {
  it('eksik bayrakları listeler', () => {
    expect(cookieIssues(['a=1']).length).toBe(3);
    expect(cookieIssues(['a=1; Secure; HttpOnly; SameSite=Strict'])).toEqual([]);
  });
});

describe('scoreChecks', () => {
  it('ağırlıklı puanı ve notu hesaplar', () => {
    expect(scoreChecks([{ id: 'x', title: 'x', status: 'pass', detail: '', weight: 10 }]).score).toBe(100);
    expect(scoreChecks([{ id: 'x', title: 'x', status: 'warn', detail: '', weight: 10 }]).score).toBe(50);
    expect(scoreChecks([{ id: 'x', title: 'x', status: 'fail', detail: '', weight: 10 }]).score).toBe(0);
  });
});
