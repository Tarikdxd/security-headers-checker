# security-headers-checker

[![ci](https://github.com/Tarikdxd/security-headers-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/Tarikdxd/security-headers-checker/actions)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![bun](https://img.shields.io/badge/runtime-bun-black?logo=bun)](https://bun.sh)

HTTP güvenlik başlıklarını denetleyen, ağırlıklı olarak puanlayan ve **GitHub Actions** olarak çalışabilen küçük bir CLI. Bağımlılık yok, tek dosyada çalışır; insan, JSON ve SARIF 2.1.0 çıktısı verir.

```console
$ security-headers https://example.com --fail-under 70

  https://example.com
  HTTP 200 · 62/100 (D)

  ✓ HTTPS
  ! HSTS                           max-age kısa (300s < 15552000s), includeSubDomains yok
  ! CSP                            Zayıf/eksik: 'unsafe-inline', frame-ancestors yok
  ✓ Clickjacking koruması
  ✓ MIME sniffing
  ✓ Referrer-Policy
  ! Permissions-Policy             Tanımlı değil (önerilir).
  ...
```

## Neleri denetler?

| Kontrol | Ağırlık | Aranan |
| --- | --- | --- |
| HTTPS | 10 | Son URL `https://` |
| HSTS | 15 | `max-age >= 180 gün`, `includeSubDomains`, `preload` |
| CSP | 15 | `default-src`, `frame-ancestors`, `unsafe-inline/eval` ve `*` yokluğu |
| Clickjacking | 8 | `X-Frame-Options` veya CSP `frame-ancestors` |
| MIME sniffing | 8 | `X-Content-Type-Options: nosniff` |
| Referrer-Policy | 6 | `unsafe-url` / `no-referrer-when-downgrade` değil |
| Permissions-Policy | 6 | Tanımlı olması |
| COOP / COEP / CORP | 11 | Çapraz köken izolasyonu başlıkları |
| Sürüm ifşası | 4 | `Server` / `X-Powered-By` sızıntısı |
| CORS | 6 | `*` + `credentials` birlikte değil |
| Çerez bayrakları | 8 | `Secure`, `HttpOnly`, `SameSite` |

Puan = ağırlıklı başarı oranı. `warn` yarım puan sayılır. Not: **A** ≥ 90, **B** ≥ 80, **C** ≥ 70, **D** ≥ 60, **E** ≥ 50, aksi **F**.

## Kurulum

```sh
git clone https://github.com/Tarikdxd/security-headers-checker.git
cd security-headers-checker
bun install
bun link            # "security-headers" komutunu PATH'e ekler
```

Bun olmadan denemek için:

```sh
bunx github:Tarikdxd/security-headers-checker https://example.com
```

## Kullanım

```sh
security-headers https://example.com
security-headers example.com --json
security-headers example.com --sarif
security-headers example.com --json --output report.json
security-headers https://example.com --fail-under 80   # CI için
security-headers https://example.com --timeout 5000 --no-color
```

Çıkış kodları:

| Kod | Anlam |
| --- | --- |
| `0` | Denetim tamam, puan eşiğin üstünde |
| `1` | Puan `--fail-under` değerinin altında |
| `2` | Kullanım hatası veya istek başarısız |

`--json` çıktısı tüm kontrolleri, ağırlıkları ve nihai puanı içerir; raporlara doğrudan gömülebilir.

`--output <path>` seçilen biçimi (text, JSON veya SARIF) dosyaya yazar; terminale yazmaz ve renk kullanmaz. Yazılamayan bir yol exit 2 ile raporlanır.

## SARIF ve Code Scanning

`--sarif` çıktısı SARIF 2.1.0 üretir; her `warn`/`fail` kontrolü bir sonuç olur ve GitHub Code Scanning'de Security sekmesinde görünür. `--json` ile birlikte kullanılamaz.

```yaml
name: headers

on: [pull_request]

jobs:
  headers:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: oven-sh/setup-bun@v2
      - run: bunx github:Tarikdxd/security-headers-checker https://example.com --sarif > headers.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: headers.sarif
```

Action'ın `format: sarif` girdisi sonucu iş loglarına yazar; dosya yüklemek için yukarıdaki doğrudan CLI çağrısını kullan.

## GitHub Actions

Repoya ekle:

```yaml
name: headers

on:
  pull_request:
  schedule:
    - cron: '0 6 * * 1'

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: Tarikdxd/security-headers-checker@v0.3.0
        with:
          url: https://example.com
          fail-under: '70'
          format: text   # text | json | sarif
```

Action çıktısı işin loglarına yazılır ve puan eşiğin altındaysa iş kırmızı olur. Sürüm sabitlemek için `@v0.3.0` etiketini kullan.

## Geliştirme

```sh
bun install
bun test
bunx tsc --noEmit
bun src/cli.ts https://example.com
```

Testler ağa çıkmaz; `evaluate()` saf fonksiyonu sentetik başlıklarla doğrulanır.

## Sınırlar

- Yalnızca **yanıt başlıklarına** bakar. HTML meta etiketleri, JavaScript davranışı ve TLS yapılandırmasının tamamı kapsam dışıdır.
- Tek istek atar; kimlik doğrulamalı sayfalar için `Authorization` başlığı desteği yoktur (bilinçli olarak: sırları CLI argümanına koymayın).
- Puanlama sezgiseldir; A notu tam güvenlik garantisi değildir.

## Lisans

MIT © 2026 Tarık Tozlu
