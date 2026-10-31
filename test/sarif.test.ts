import { describe, expect, it } from 'bun:test';
import { evaluate } from '../src/check.ts';
import { toSarif } from '../src/sarif.ts';

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

describe('toSarif', () => {
  it('tam korumalı yanıtta sonuç üretmez', () => {
    const audit = evaluate('https://a.test', 'https://a.test', secureHeaders, 200);
    const sarif = toSarif(audit) as any;
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0].results).toEqual([]);
    expect(sarif.runs[0].tool.driver.rules.length).toBeGreaterThan(5);
  });

  it('eksik başlıkları kural kimlikleriyle raporlar', () => {
    const audit = evaluate('http://a.test', 'http://a.test', {}, 200);
    const sarif = toSarif(audit) as any;
    const ids = sarif.runs[0].results.map((result: any) => result.ruleId);
    expect(ids).toContain('https');
    expect(ids).toContain('hsts');
    expect(ids).toContain('csp');
    expect(ids).toContain('frame');
    expect(ids).toContain('nosniff');
    expect(sarif.runs[0].results.find((result: any) => result.ruleId === 'hsts').level).toBe('error');
    expect(sarif.runs[0].results.some((result: any) => result.level === 'warning')).toBe(true);
  });

  it('uyarıları warning olarak işaretler', () => {
    const audit = evaluate('https://a.test', 'https://a.test', {
      ...secureHeaders,
      'strict-transport-security': 'max-age=300',
    }, 200);
    const sarif = toSarif(audit) as any;
    const hsts = sarif.runs[0].results.find((result: any) => result.ruleId === 'hsts');
    expect(hsts.level).toBe('warning');
    expect(hsts.properties['security-severity']).toBe('4.0');
  });

  it('hedef URL ve güvenlik şiddetini taşır', () => {
    const audit = evaluate('https://a.test', 'https://a.test', {}, 200);
    const sarif = toSarif(audit) as any;
    const result = sarif.runs[0].results[0];
    expect(result.locations[0].physicalLocation.artifactLocation.uri).toBe('https://a.test');
    expect(result.properties['security-severity']).toBe('7.5');
  });
});
