"""Measure Cloudflare entrances for an operator's own WebSocket service."""

from base64 import b64decode, b64encode
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from hashlib import sha1, sha256
from http.client import HTTPSConnection, HTTPException
from ipaddress import IPv4Address, IPv4Network
from statistics import median
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
import argparse
import json
import os
import re
import secrets
import socket
import ssl
import time


NETWORKS = tuple(map(IPv4Network, (
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
)))
PORTS = {443, 2053, 2083, 2087, 2096, 8443}
TIMEOUT = 5
MAX_GAP = 75 * 60
UPSTREAM = 'https://raw.githubusercontent.com/xingpingcn/enhanced-FaaS-in-China/main/Cf.json'
WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
TLS = ssl.create_default_context()


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        return None


HTTP = build_opener(ProxyHandler({}), NoRedirect())


@dataclass(frozen=True)
class Settings:
    feed: str
    host: str
    path: str

    @classmethod
    def from_environment(cls):
        feed = os.environ['PREFERRED_FEED']
        target = urlsplit(os.environ['PROBE_TARGET'])
        if not re.fullmatch(r'https://[a-zA-Z0-9.-]+', feed) or not target.hostname or not re.fullmatch(
            r'[a-zA-Z0-9.-]+', target.hostname
        ) or target.scheme != 'wss' or target.netloc != target.hostname or target.fragment:
            raise ValueError('Unexpected feed or probe target')
        path = target.path or '/'
        if target.query:
            path += '?' + target.query
        if any(ord(ch) < 33 or ord(ch) > 126 for ch in path):
            raise ValueError('Unexpected probe path')
        return cls(feed, target.hostname, path)


def get_url(url, *, method='GET', headers=None, body=None, limit=32768):
    headers = {'User-Agent': 'edge-candidate-monitor/1.0', **(headers or {})}
    query = Request(url, data=body, method=method, headers=headers)
    with HTTP.open(query, timeout=12) as response:
        data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError('Response exceeded size limit')
        return response.status, data


def valid_endpoint(candidate):
    try:
        ip, port = candidate.split(':')
        address = IPv4Address(ip)
        return str(int(port)) == port and int(port) in PORTS and any(address in network for network in NETWORKS)
    except (AttributeError, ValueError):
        return False


def read_list(settings):
    _, data = get_url(settings.feed + '/ips.txt', limit=128)
    lines = data.decode('ascii').strip().splitlines()
    if len(lines) != 2 or len(set(lines)) != 2 or not all(map(valid_endpoint, lines)):
        raise ValueError('Expected exactly two valid Cloudflare endpoints')
    return lines


def websocket_probe(settings, endpoint):
    port = 443 if endpoint is None else int(endpoint.split(':')[1])
    connection = HTTPSConnection(settings.host, port, timeout=TIMEOUT, context=TLS)
    if endpoint is not None:
        address = endpoint.split(':')[0]
        connection._create_connection = lambda _, timeout, source: socket.create_connection((address, port), timeout, source)
    key = b64encode(secrets.token_bytes(16)).decode('ascii')
    expected = b64encode(sha1((key + WS_GUID).encode('ascii')).digest()).decode('ascii')
    now = time.monotonic()
    try:
        connection.request('GET', settings.path, headers={
            'Host': settings.host, 'Connection': 'Upgrade', 'Upgrade': 'websocket',
            'Sec-WebSocket-Key': key, 'Sec-WebSocket-Version': '13',
        })
        response = connection.getresponse()
        if response.status == 101 and response.getheader('Sec-WebSocket-Accept') == expected:
            return max(1, round(1000 * (time.monotonic() - now)))
    except (OSError, HTTPException):
        pass
    finally:
        connection.close()
    return None


def measure(settings, endpoints):
    results = {endpoint: [] for endpoint in endpoints}
    with ThreadPoolExecutor(max_workers=6) as pool:
        for _ in range(3):
            for endpoint, measurement in zip(endpoints, pool.map(lambda ep: websocket_probe(settings, ep), endpoints)):
                if measurement is not None:
                    results[endpoint].append(measurement)
    return {endpoint: (len(values), median(values) if values else None) for endpoint, values in results.items()}


def candidates(active):
    fallback = os.environ.get('CANDIDATE_SEEDS', '').split(',')
    live = []
    try:
        _, data = get_url(UPSTREAM)
        cf = json.loads(data)['Cf']
        if 0 <= time.time() - float(cf['update_time']) <= 72 * 3600:
            for group in ('dianxin', 'liantong', 'yidong', 'default'):
                live.extend(f'{address}:443' for address in cf['result'].get(group, [])[:4])
    except (URLError, ValueError, KeyError, TypeError):
        pass
    return [item for item in dict.fromkeys([*live, *fallback]) if item not in active and valid_endpoint(item)][:18]


def fingerprint(endpoint):
    return sha256(endpoint.encode('ascii')).hexdigest()


def track(active, scores, baseline, previous, now):
    old_records = previous.get('endpoints', {}) if previous.get('version') == 1 else {}
    records = {}
    for endpoint in active:
        key = fingerprint(endpoint)
        previous_point = old_records.get(key, {})
        healthy = previous_point.get('healthy', [])
        old_streak = previous_point.get('streak', 0) if 0 < now - previous_point.get('at', 0) <= MAX_GAP else 0
        count, delay = scores[endpoint]
        excess = delay - baseline if delay is not None else None
        ratio = delay / max(10, baseline) if delay is not None else None
        slow = count == 3 and len(healthy) >= 2 and ratio > 1.35 * median(v[0] for v in healthy) and excess > (
            median(v[1] for v in healthy) + 75
        )
        bad = count != 3 or slow
        if not bad:
            healthy = [*healthy[-7:], [ratio, excess]]
        records[key] = {'healthy': healthy, 'streak': old_streak + 1 if bad else 0, 'at': now}
    return {'version': 1, 'endpoints': records}


def is_better(existing, candidate):
    count, old_ms = existing
    passed, new_ms = candidate
    if passed != 3:
        return False
    if count != 3:
        return new_ms <= TIMEOUT * 900
    return new_ms <= min(0.8 * old_ms, old_ms - 30)


def github_state(previous_sha=None, state=None):
    repository = os.environ['GITHUB_REPOSITORY']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Unexpected repository identifier')
    url = f'https://api.github.com/repos/{repository}/contents/health.json'
    headers = {'Authorization': 'Bearer ' + os.environ['GH_TOKEN'], 'Accept': 'application/vnd.github+json'}
    if state is None:
        try:
            _, data = get_url(url + '?ref=monitor-state', headers=headers)
        except HTTPError as exc:
            if exc.code == 404:
                return None, {}
            raise
        entry = json.loads(data)
        return entry['sha'], json.loads(b64decode(entry['content']))

    record = {'message': 'Record cloud probe health', 'branch': 'monitor-state',
              'content': b64encode((json.dumps(state, sort_keys=True) + '\n').encode('utf-8')).decode('ascii')}
    if previous_sha:
        record['sha'] = previous_sha
    headers['Content-Type'] = 'application/json'
    get_url(url, method='PUT', headers=headers, body=json.dumps(record).encode('utf-8'))


def publish(settings, current, updated):
    if read_list(settings) != current:
        print('Active list changed during the probe. Skipped publishing.')
        return
    token = os.environ['PUBLISH_KEY']
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
        raise ValueError('Unexpected publish key')
    body = ('\n'.join(updated) + '\n').encode('ascii')
    status, _ = get_url(settings.feed + '/api/ips', method='PUT', body=body,
                        headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'text/plain; charset=utf-8'})
    if status != 204:
        raise ValueError('Unconfirmed publishing response')
    for wait in (0, 3, 8, 15):
        time.sleep(wait)
        try:
            if read_list(settings) == updated:
                print('Published and read back the updated candidate list.')
                return
        except (URLError, ValueError):
            pass
    print('Publishing accepted. Read-back is pending propagation.')


def run(mode):
    settings = Settings.from_environment()
    active = read_list(settings)
    measured = measure(settings, [None, *active])
    print('Cloud WebSocket probes (successes out of 3, median ms):', [measured[key] for key in [None, *active]])
    if measured[None][0] < 2:
        raise ValueError('Cloud baseline was unavailable; retaining current list')
    if mode in ('dry-run', 'verify-writer'):
        if not any(measured[key][0] == 3 for key in active):
            raise ValueError('No active endpoint passed all checks')
        if mode == 'verify-writer':
            publish(settings, active, active)
        else:
            print('Read-only check completed.')
        return

    previous_sha, previous = github_state()
    state = track(active, measured, measured[None][1], previous, int(time.time()))
    github_state(previous_sha, state)
    unhealthy = [key for key in active if state['endpoints'][fingerprint(key)]['streak'] >= 3]
    if not unhealthy:
        print('Current list retained.')
        return
    pool = candidates(active)
    if not pool:
        print('No eligible alternatives. Current list retained.')
        return
    scored = measure(settings, pool)
    qualified = [key for key in pool if any(is_better(measured[old], scored[key]) for old in unhealthy)]
    finalists = sorted(qualified, key=lambda key: scored[key][1])[:4]
    if not finalists:
        print('Alternatives did not improve the current list.')
        return
    checked = measure(settings, finalists)
    updated = active.copy()
    for old in unhealthy:
        replacement = next((key for key in finalists if key not in updated and is_better(measured[old], checked[key])), None)
        if replacement:
            updated[updated.index(old)] = replacement
    if updated != active:
        publish(settings, active, updated)
    else:
        print('No alternative passed the repeat test. Current list retained.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('dry-run', 'verify-writer', 'monitor'))
    try:
        run(parser.parse_args().mode)
    except (OSError, ValueError, KeyError, HTTPException) as exc:
        detail = f'HTTP {exc.code}' if isinstance(exc, HTTPError) else type(exc).__name__
        print(f'Monitor stopped safely ({detail}).')
        raise SystemExit(1) from None
