#!/usr/bin/env python3
"""Performance / load test (k6) against a target defined only in GitHub Secrets.

The workflow input contains just an alias (e.g. "t1"). The real URL, paths and optional
headers live in the LOADTEST_TARGETS secret, so nothing about the target is visible publicly.

LOADTEST_TARGETS (JSON):
{
  "t1": {"base_url": "https://www.example.com", "paths": ["/", "/pricing", {"path": "/api/health", "weight": 3}]},
  "t2": "https://shop.example.com"
}
"""
import json
import os
import sys
import time
from pathlib import Path

from common import env, Redactor, SummaryLogger
from sec_common import (HtmlReport, deliver_report, file_stamp, human_bytes, human_duration, run_cmd, shred_paths,
                        ts_label, write_log)

TARGETS_JSON = env('LOADTEST_TARGETS', default='')
BYPASS_HEADER = env('LOADTEST_BYPASS_HEADER', default='')  # "Header-Name: value"
ALIAS = (env('LT_TARGET', default='t1') or 't1').strip()
PROFILE = (env('LT_PROFILE', default='load') or 'load').strip().lower()
MAX_VUS_CAP = int(env('LT_MAX_VUS_CAP', default='5000'))
MAX_MINUTES_CAP = int(env('LT_MAX_MINUTES_CAP', default='90'))

WORK = Path(env('LT_WORKDIR', default='lt_work')).resolve()
REPORT_DIR = Path(env('REPORT_DIR', default='lt_reports')).resolve()
redact = Redactor([TARGETS_JSON, BYPASS_HEADER])
log = SummaryLogger(redact)
START = time.monotonic()


def as_int(name, default, lo, hi):
    try:
        v = int(float(env(name, default=str(default)) or default))
    except ValueError:
        v = default
    return max(lo, min(hi, v))


def as_float(name, default, lo, hi):
    try:
        v = float(env(name, default=str(default)) or default)
    except ValueError:
        v = default
    return max(lo, min(hi, v))


def parse_duration(text: str, default_s: int) -> int:
    text = (text or '').strip().lower()
    if not text:
        return default_s
    total, num = 0, ''
    for ch in text:
        if ch.isdigit():
            num += ch
        elif ch in 'hms' and num:
            total += int(num) * {'h': 3600, 'm': 60, 's': 1}[ch]
            num = ''
    if num:
        total += int(num)
    return total or default_s


def load_target():
    try:
        targets = json.loads(TARGETS_JSON)
    except Exception as exc:
        raise RuntimeError('LOADTEST_TARGETS secret is missing or not valid JSON.') from exc
    t = targets.get(ALIAS)
    if t is None:
        raise RuntimeError(f'Alias "{ALIAS}" not found in LOADTEST_TARGETS (available: {", ".join(targets)}).')
    if isinstance(t, str):
        t = {'base_url': t}
    base = t.get('base_url', '').rstrip('/')
    if not base.startswith(('https://', 'http://')):
        raise RuntimeError(f'Alias "{ALIAS}" has no valid base_url.')
    paths = []
    for p in t.get('paths') or ['/']:
        if isinstance(p, str):
            paths.append({'path': p, 'weight': 1})
        else:
            paths.append({'path': p.get('path', '/'), 'weight': max(1, int(p.get('weight', 1)))})
    headers = dict(t.get('headers') or {})
    if BYPASS_HEADER and ':' in BYPASS_HEADER:
        k, v = BYPASS_HEADER.split(':', 1)
        headers[k.strip()] = v.strip()
    return base, paths, headers


def build_scenario(vus, steady_s, ramp_s, rps):
    if PROFILE == 'smoke':
        return {'executor': 'constant-vus', 'vus': min(vus, 5), 'duration': '1m'}
    if rps > 0 and PROFILE in ('load', 'soak'):
        return {'executor': 'ramping-arrival-rate', 'startRate': max(1, rps // 10), 'timeUnit': '1s',
                'preAllocatedVUs': max(10, vus // 2), 'maxVUs': vus,
                'stages': [{'target': rps, 'duration': f'{ramp_s}s'}, {'target': rps, 'duration': f'{steady_s}s'},
                           {'target': 0, 'duration': f'{max(10, ramp_s // 2)}s'}]}
    if PROFILE == 'breakpoint':
        top = rps or vus * 20
        return {'executor': 'ramping-arrival-rate', 'startRate': 1, 'timeUnit': '1s',
                'preAllocatedVUs': max(10, vus // 2), 'maxVUs': vus,
                'stages': [{'target': top, 'duration': f'{steady_s}s'}]}
    if PROFILE == 'stress':
        step = max(30, steady_s // 4)
        stages = []
        for factor in (0.25, 0.5, 0.75, 1.0):
            stages += [{'target': max(1, int(vus * factor)), 'duration': f'{ramp_s // 2 or 10}s'},
                       {'target': max(1, int(vus * factor)), 'duration': f'{step}s'}]
        stages.append({'target': 0, 'duration': f'{max(10, ramp_s // 2)}s'})
        return {'executor': 'ramping-vus', 'startVUs': 0, 'stages': stages, 'gracefulRampDown': '30s'}
    if PROFILE == 'spike':
        base = max(1, vus // 10)
        return {'executor': 'ramping-vus', 'startVUs': 0, 'gracefulRampDown': '20s', 'stages': [
            {'target': base, 'duration': '30s'}, {'target': base, 'duration': '1m'},
            {'target': vus, 'duration': '10s'}, {'target': vus, 'duration': f'{max(60, steady_s // 3)}s'},
            {'target': base, 'duration': '10s'}, {'target': base, 'duration': '1m'}, {'target': 0, 'duration': '10s'}]}
    # load / soak
    return {'executor': 'ramping-vus', 'startVUs': 0, 'gracefulRampDown': '30s', 'stages': [
        {'target': vus, 'duration': f'{ramp_s}s'}, {'target': vus, 'duration': f'{steady_s}s'},
        {'target': 0, 'duration': f'{max(10, ramp_s // 2)}s'}]}


K6_SCRIPT = r"""
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';
const CFG = JSON.parse(__ENV.K6_CFG);
const s2 = new Counter('status_2xx'), s3 = new Counter('status_3xx'), s4 = new Counter('status_4xx');
const s5 = new Counter('status_5xx'), s0 = new Counter('status_network_error');
const pool = [];
CFG.paths.forEach(p => { for (let i = 0; i < p.weight; i++) pool.push(p.path); });
const thresholds = {
  http_req_failed: [`rate<${CFG.max_error_rate}`],
  http_req_duration: [`p(95)<${CFG.p95_ms}`],
};
CFG.paths.forEach(p => { thresholds[`http_req_duration{name:${p.path}}`] = ['max>=0']; });
export const options = {
  scenarios: { main: CFG.scenario },
  thresholds: thresholds,
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)', 'count'],
  discardResponseBodies: true,
  insecureSkipTLSVerify: false,
  userAgent: 'Mozilla/5.0 (compatible; performance-test)',
  noConnectionReuse: false,
};
export default function () {
  const path = pool[Math.floor(Math.random() * pool.length)];
  const res = http.get(CFG.base_url + path, { headers: CFG.headers, tags: { name: path }, timeout: '60s' });
  const c = res.status;
  if (c === 0) s0.add(1); else if (c < 300) s2.add(1); else if (c < 400) s3.add(1); else if (c < 500) s4.add(1); else s5.add(1);
  check(res, { 'status < 400': r => r.status > 0 && r.status < 400 });
  if (CFG.think_ms > 0) sleep(CFG.think_ms / 1000 * (0.5 + Math.random()));
}
export function handleSummary(data) {
  return { [__ENV.K6_SUMMARY]: JSON.stringify(data) };
}
"""


def metric(m, name, key, default=0):
    return ((m.get(name) or {}).get('values') or {}).get(key, default)


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    fatal, summary, verdict = None, {}, 'FAIL'
    vus = as_int('LT_VUS', 100, 1, MAX_VUS_CAP)
    steady_s = min(parse_duration(env('LT_DURATION', default='5m'), 300), MAX_MINUTES_CAP * 60)
    ramp_s = min(parse_duration(env('LT_RAMP_UP', default='1m'), 60), 30 * 60)
    rps = as_int('LT_RPS', 0, 0, 200000)
    p95_ms = as_int('LT_P95_MS', 1500, 10, 120000)
    max_err = as_float('LT_MAX_ERROR_RATE', 0.01, 0.0, 1.0)
    think_ms = as_int('LT_THINK_MS', 500, 0, 60000)
    base = ''
    dashboard = REPORT_DIR / f'k6_dashboard_{file_stamp()}.html'
    summary_file = WORK / 'summary.json'
    try:
        base, paths, headers = load_target()
        scenario = build_scenario(vus, steady_s, ramp_s, rps)
        cfg = {'base_url': base, 'paths': paths, 'headers': headers, 'scenario': scenario, 'p95_ms': p95_ms,
               'max_error_rate': max_err, 'think_ms': think_ms}
        script = WORK / 'test.js'
        script.write_text(K6_SCRIPT, encoding='utf-8')
        log.log(f'Profile {PROFILE}, peak VUs {vus}, steady {steady_s}s, ramp {ramp_s}s, rps {rps or "unlimited"}.')
        rc, out, err = run_cmd(['k6', 'run', '--quiet', '--no-color', str(script)], timeout=(MAX_MINUTES_CAP + 20) * 60,
                               env_extra={'K6_CFG': json.dumps(cfg), 'K6_SUMMARY': str(summary_file),
                                          'K6_WEB_DASHBOARD': 'true', 'K6_WEB_DASHBOARD_EXPORT': str(dashboard),
                                          'K6_WEB_DASHBOARD_HOST': '127.0.0.1', 'K6_NO_USAGE_REPORT': 'true'})
        log.log(f'k6 exit code {rc}.')
        if err.strip():
            log.log('k6 stderr (tail): ' + redact(err[-2000:]))
        summary = json.loads(summary_file.read_text(encoding='utf-8'))
        verdict = 'PASS' if rc == 0 else ('FAIL' if rc == 99 else 'ERROR')
    except Exception as exc:
        fatal = redact(str(exc))
        log.log(f'FATAL: {fatal}')

    m = summary.get('metrics', {}) if summary else {}
    rep = HtmlReport('Load Test Report', f'Target alias: {ALIAS} | Profile: {PROFILE} | {ts_label()}')
    reqs = metric(m, 'http_reqs', 'count')
    err_rate = metric(m, 'http_req_failed', 'rate')
    rep.kpis({'Verdict': verdict if not fatal else 'ERROR', 'Requests': int(reqs),
              'Throughput (req/s)': round(metric(m, 'http_reqs', 'rate'), 1),
              'Error rate': f'{err_rate * 100:.2f} %', 'p95 latency': f"{metric(m, 'http_req_duration', 'p(95)'):.0f} ms",
              'p99 latency': f"{metric(m, 'http_req_duration', 'p(99)'):.0f} ms",
              'Peak VUs': int(metric(m, 'vus_max', 'max', vus)), 'Data received': human_bytes(metric(m, 'data_received', 'count'))})
    if fatal:
        rep.text('Run error', [fatal])
    rep.table('Configuration', ['Parameter', 'Value'], [
        ['Target', base or '-'], ['Profile', PROFILE], ['Peak virtual users', vus], ['Steady duration', f'{steady_s}s'],
        ['Ramp-up', f'{ramp_s}s'], ['Target RPS', rps or 'unlimited (closed model)'], ['Think time', f'{think_ms} ms'],
        ['Threshold p95', f'< {p95_ms} ms'], ['Threshold error rate', f'< {max_err * 100:.2f} %']])
    thr_rows = []
    for name, data in m.items():
        for expr, res in (data.get('thresholds') or {}).items():
            if expr == 'max>=0':
                continue
            thr_rows.append(['PASS' if res.get('ok') else 'FAIL', name, expr])
    rep.table('Thresholds', ['Result', 'Metric', 'Condition'], thr_rows, badge_cols=(0,))
    lat = []
    for name, label in [('http_req_duration', 'Total response time'), ('http_req_waiting', 'Time to first byte'),
                        ('http_req_connecting', 'TCP connect'), ('http_req_tls_handshaking', 'TLS handshake'),
                        ('http_req_receiving', 'Receiving'), ('iteration_duration', 'Iteration (incl. think time)')]:
        if name in m:
            v = m[name]['values']
            lat.append([label] + [f"{v.get(k, 0):.1f}" for k in ('avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max')])
    rep.table('Latency (ms)', ['Metric', 'avg', 'min', 'median', 'p90', 'p95', 'p99', 'max'], lat)
    ep = []
    for name, data in m.items():
        if name.startswith('http_req_duration{name:'):
            v = data.get('values', {})
            ep.append([name[len('http_req_duration{name:'):-1], int(v.get('count', 0)), f"{v.get('avg', 0):.0f}",
                       f"{v.get('p(95)', 0):.0f}", f"{v.get('p(99)', 0):.0f}", f"{v.get('max', 0):.0f}"])
    rep.table('Per endpoint (ms)', ['Path', 'Requests', 'avg', 'p95', 'p99', 'max'], sorted(ep, key=lambda r: -float(r[3])))
    rep.table('Status codes', ['Class', 'Count'], [[k.replace('status_', ''), int(metric(m, k, 'count'))]
                                                   for k in ('status_2xx', 'status_3xx', 'status_4xx', 'status_5xx',
                                                             'status_network_error')])
    rep.text('How to read this', [
        'p95 = 95 % of requests were faster than this value. Error rate counts HTTP status >= 400 and network errors.',
        'Requests blocked by a CDN/WAF (403/429) usually mean the bypass header is missing - see setup guide.',
        'The attached k6 dashboard HTML contains time-series charts (latency, throughput, VUs over time).'])
    html_path = rep.write(REPORT_DIR / f'load_test_{file_stamp()}.html')
    raw = REPORT_DIR / 'k6_summary.json'
    if summary:
        raw.write_text(json.dumps(summary, indent=1), encoding='utf-8')
    log_path = write_log(log, REPORT_DIR / 'run_log.txt')
    icon = {'PASS': '✅', 'FAIL': '🔴', 'ERROR': '❌'}.get(verdict if not fatal else 'ERROR', '❌')
    subject = (f"{icon} Load Test {ALIAS} ({PROFILE}): {verdict if not fatal else 'ERROR'} - "
               f"p95 {metric(m, 'http_req_duration', 'p(95)'):.0f} ms, errors {err_rate * 100:.2f} %")
    body = (f'{subject}\n\nRequests: {int(reqs)}\nDuration: {human_duration(time.monotonic() - START)}\n\n'
            'Attached: HTML summary, k6 dashboard (charts), raw k6 summary JSON and run log.')
    deliver_report(subject, body, [html_path, raw, log_path], bulk=[dashboard], logger=log, workdir=REPORT_DIR,
                   bulk_name='k6_dashboard')
    shred_paths(WORK, REPORT_DIR)
    sys.exit(0 if (verdict == 'PASS' and not fatal) else 1)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit(1)
