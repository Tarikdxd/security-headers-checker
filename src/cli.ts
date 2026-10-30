#!/usr/bin/env bun
import { evaluate, headerMap } from './check.ts';

const HELP = `security-headers-checker v0.1.0

Kullanım:
  security-headers <url> [seçenekler]

Seçenekler:
  --json                 Sonucu JSON olarak yazdır
  --fail-under <0-100>   Puan bu değerin altındaysa çıkış kodu 1 (varsayılan: 0)
  --timeout <ms>         İstek zaman aşımı (varsayılan: 10000)
  --no-color             Renkleri kapat
  -h, --help             Bu yardımı göster
  -v, --version          Sürümü göster

Örnek:
  security-headers https://example.com --fail-under 70
`;

interface Options {
  url: string;
  json: boolean;
  failUnder: number;
  timeout: number;
  color: boolean;
}

function parseArgs(argv: string[]): Options | null {
  const opts: Options = { url: '', json: false, failUnder: 0, timeout: 10_000, color: true };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === '-h' || arg === '--help') {
      process.stdout.write(HELP);
      process.exit(0);
    }
    if (arg === '-v' || arg === '--version') {
      console.log('0.1.0');
      process.exit(0);
    }
    if (arg === '--json') {
      opts.json = true;
      continue;
    }
    if (arg === '--no-color') {
      opts.color = false;
      continue;
    }
    if (arg === '--fail-under') {
      const value = Number(argv[++i]);
      if (!Number.isFinite(value) || value < 0 || value > 100) {
        console.error('hata: --fail-under 0-100 arasında olmalı');
        return null;
      }
      opts.failUnder = value;
      continue;
    }
    if (arg === '--timeout') {
      const value = Number(argv[++i]);
      if (!Number.isFinite(value) || value <= 0) {
        console.error('hata: --timeout pozitif olmalı');
        return null;
      }
      opts.timeout = value;
      continue;
    }
    if (arg.startsWith('-')) {
      console.error(`hata: bilinmeyen seçenek ${arg}`);
      return null;
    }
    if (!opts.url) opts.url = arg;
  }
  if (!opts.url) {
    console.error('hata: URL gerekli\n');
    process.stderr.write(HELP);
    return null;
  }
  return opts;
}

function colorize(color: boolean, code: string, text: string): string {
  return color ? `\u001b[${code}m${text}\u001b[0m` : text;
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  if (!opts) process.exit(2);

  const useColor = opts.color && !process.env.NO_COLOR && Boolean(process.stdout.isTTY);
  let url = opts.url;
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`;

  let response: Response;
  try {
    response = await fetch(url, {
      redirect: 'follow',
      signal: AbortSignal.timeout(opts.timeout),
      headers: { 'user-agent': 'security-headers-checker/0.1' },
    });
  } catch (error) {
    console.error(`hata: istek başarısız: ${(error as Error).message}`);
    process.exit(2);
  }

  const headerBag = response.headers as unknown as { getSetCookie?: () => string[] };
  const setCookies = typeof headerBag.getSetCookie === 'function' ? headerBag.getSetCookie() : [];
  const audit = evaluate(url, response.url || url, headerMap(response.headers), response.status, setCookies);
  await response.body?.cancel().catch(() => undefined);

  if (opts.json) {
    console.log(JSON.stringify(audit, null, 2));
  } else {
    const gradeColor = audit.score >= 80 ? '32' : audit.score >= 60 ? '33' : '31';
    console.log('');
    console.log(`  ${colorize(useColor, '1', audit.url)}`);
    console.log(`  HTTP ${audit.httpStatus} · ${colorize(useColor, gradeColor, `${audit.score}/100 (${audit.grade})`)}`);
    console.log('');
    for (const check of audit.checks) {
      const symbol = check.status === 'pass' ? '✓' : check.status === 'warn' ? '!' : '✗';
      const symbolColor = check.status === 'pass' ? '32' : check.status === 'warn' ? '33' : '31';
      console.log(
        `  ${colorize(useColor, symbolColor, symbol)} ${check.title.padEnd(30)} ${check.detail}`,
      );
    }
    console.log('');
  }

  if (audit.score < opts.failUnder) process.exit(1);
}

void main();
