#!/usr/bin/env python3
"""Google Lighthouse audit for every URL in the LIGHTHOUSE_URLS secret.

Produces one HTML summary (scores + Core Web Vitals for all domains) plus the original
Lighthouse HTML report per URL and form factor. Everything is e-mailed as attachments
(auto-zipped and split across several mails if needed) and then deleted.
"""
import json
import re
import statistics
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from common import env, Redactor, SummaryLogger
from sec_common import (HtmlReport, deliver_report, file_stamp, human_duration, parse_list, run_cmd, shred_paths,
                        ts_label, write_csv, write_log)

URLS = env('LIGHTHOUSE_URLS', default='')
FORM_FACTORS = env('LH_FORM_FACTORS', default='mobile,desktop')
RUNS = max(1, min(5, int(env('LH_RUNS', default='1') or 1)))
TIMEOUT_S = int(env('LH_TIMEOUT_SECONDS', default='240'))
REPORT_DIR = Path(env('REPORT_DIR', default='lh_reports')).resolve()
WORK = Path(env('LH_WORKDIR', default='lh_work')).resolve()
redact = Redactor([URLS])
log = SummaryLogger(redact)
START = time.monotonic()
CATS = [('performance', 'Performance'), ('accessibility', 'Accessibility'), ('best-practices', 'Best practices'),
        ('seo', 'SEO')]
VITALS = [('largest-contentful-paint', 'LCP'), ('first-contentful-paint', 'FCP'), ('total-blocking-time', 'TBT'),
          ('cumulative-layout-shift', 'CLS'), ('speed-index', 'Speed Index'), ('interactive', 'TTI')]


def slug(url: str) -> str:
    p = urlparse(url if '://' in url else f'https://{url}')
    s = (p.netloc + p.path).strip('/').replace('/', '_')
    return re.sub(r'[^A-Za-z0-9._-]', '_', s)[:80] or 'site'


def run_lighthouse(url: str, factor: str, out_base: Path):
    cmd = ['lighthouse', url, '--output=json', '--output=html', f'--output-path={out_base}', '--quiet',
           '--chrome-flags=--headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage',
           f'--max-wait-for-load={TIMEOUT_S * 500}']
    if factor == 'desktop':
        cmd.append('--preset=desktop')
    rc, _, err = run_cmd(cmd, timeout=TIMEOUT_S + 60)
    jpath = Path(f'{out_base}.report.json')
    hpath = Path(f'{out_base}.report.html')
    if not jpath.exists():
        raise RuntimeError(f'Lighthouse failed (rc={rc}): {redact(err[-300:])}')
    data = json.loads(jpath.read_text(encoding='utf-8'))
    if data.get('runtimeError'):
        raise RuntimeError(f"Lighthouse runtime error: {data['runtimeError'].get('code')}")
    scores = {k: round((data['categories'].get(k, {}).get('score') or 0) * 100) for k, _ in CATS}
    vitals = {}
    for key, label in VITALS:
        a = data.get('audits', {}).get(key, {})
        vitals[label] = (a.get('numericValue'), a.get('displayValue', 'n/a'))
    opps = []
    for a in data.get('audits', {}).values():
        details = a.get('details') or {}
        if details.get('type') == 'opportunity' and (details.get('overallSavingsMs') or 0) > 150:
            opps.append((a.get('title'), int(details['overallSavingsMs'])))
    opps.sort(key=lambda x: -x[1])
    jpath.unlink(missing_ok=True)
    return scores, vitals, opps[:5], hpath


def grade(score) -> str:
    return 'OK' if score >= 90 else ('MEDIUM' if score >= 50 else 'HIGH')


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    urls = [u if '://' in u else f'https://{u}' for u in parse_list(URLS)]
    factors = [f for f in parse_list(FORM_FACTORS) if f in ('mobile', 'desktop')] or ['mobile']
    rows, vitals_rows, opp_rows, csv_rows, bulk, errors = [], [], [], [], [], []
    detail_dir = REPORT_DIR / 'lighthouse_html'
    detail_dir.mkdir(exist_ok=True)
    if not urls:
        errors.append('LIGHTHOUSE_URLS secret is empty.')
    for i, url in enumerate(urls, 1):
        for factor in factors:
            runs = []
            try:
                for r in range(RUNS):
                    out_base = WORK / f'{slug(url)}_{factor}_{r}'
                    runs.append(run_lighthouse(url, factor, out_base))
                runs.sort(key=lambda x: x[0]['performance'])
                scores, vitals, opps, html = runs[len(runs) // 2]  # median run by performance
                final_html = detail_dir / f'{i:02d}_{slug(url)}_{factor}.html'
                html.replace(final_html)
                bulk.append(final_html)
                perf_all = [x[0]['performance'] for x in runs]
                rows.append([grade(scores['performance']), url, factor] + [scores[k] for k, _ in CATS]
                            + [f'{min(perf_all)}-{max(perf_all)}' if RUNS > 1 else '-'])
                vitals_rows.append([url, factor] + [vitals[label][1] for _, label in VITALS])
                for title, ms in opps:
                    opp_rows.append([url, factor, title, f'{ms} ms'])
                csv_rows.append([url, factor] + [scores[k] for k, _ in CATS] +
                                [vitals[label][0] for _, label in VITALS])
                log.log(f'URL #{i} {factor}: performance {scores["performance"]}.')
            except Exception as exc:
                rows.append(['FAIL', url, factor, '-', '-', '-', '-', '-'])
                errors.append(f'{url} ({factor}): {exc}')
                log.log(f'URL #{i} {factor} failed: {exc}')
    perf = [r[3] for r in rows if isinstance(r[3], int)]
    rep = HtmlReport('Lighthouse Audit', f'{ts_label()} | {len(urls)} URL(s) | form factors: {", ".join(factors)} | '
                                         f'runs per URL: {RUNS} (median shown)')
    rep.kpis({'URLs': len(urls), 'Audits': len(rows), 'Failed audits': sum(1 for r in rows if r[0] == 'FAIL'),
              'Avg performance': round(statistics.mean(perf)) if perf else '-',
              'Worst performance': min(perf) if perf else '-', 'Duration': human_duration(time.monotonic() - START)})
    rep.table('Scores (0-100)', ['Grade', 'URL', 'Device', 'Performance', 'Accessibility', 'Best practices', 'SEO',
                                 'Perf. range'], sorted(rows, key=lambda r: (r[3] if isinstance(r[3], int) else -1)),
              badge_cols=(0,), note='Grade: OK = 90-100, MEDIUM = 50-89, HIGH = below 50 (needs attention).')
    rep.table('Core Web Vitals & timings', ['URL', 'Device'] + [label for _, label in VITALS], vitals_rows,
              note='Targets (good): LCP < 2.5 s, TBT < 200 ms, CLS < 0.1.')
    rep.table('Top improvement opportunities', ['URL', 'Device', 'Opportunity', 'Estimated saving'], opp_rows)
    if errors:
        rep.text('Errors', errors)
    html_path = rep.write(REPORT_DIR / f'lighthouse_summary_{file_stamp()}.html')
    csv_path = write_csv(REPORT_DIR / f'lighthouse_scores_{file_stamp()}.csv',
                         ['url', 'device'] + [k for k, _ in CATS] + [f'{label}_numeric' for _, label in VITALS],
                         csv_rows)
    log_path = write_log(log, REPORT_DIR / 'run_log.txt')
    worst = min(perf) if perf else 0
    icon = '✅' if (perf and worst >= 90 and not errors) else ('🟠' if worst >= 50 else '🔴')
    subject = (f'{icon} Lighthouse Audit: {len(urls)} URL(s), avg performance '
               f'{round(statistics.mean(perf)) if perf else "-"}, worst {worst if perf else "-"}')
    body = (f'{subject}\n\nAttached: summary (HTML), scores (CSV), one full Lighthouse report per URL and device '
            f'(zipped), run log.' + (f'\n\n{len(errors)} audit(s) failed - see summary.' if errors else ''))
    deliver_report(subject, body, [html_path, csv_path, log_path], bulk=bulk, logger=log, workdir=REPORT_DIR,
                   bulk_name='lighthouse_reports')
    shred_paths(WORK, REPORT_DIR)
    sys.exit(1 if errors else 0)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit(1)
