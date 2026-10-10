#!/usr/bin/env python3
"""Collect one bounded, frozen Prometheus/blackbox observation without probing."""

import base64
from datetime import datetime
import json
import math
import os
from pathlib import PurePosixPath
import re
import subprocess
import sys
import time
from urllib.parse import urlencode, urlsplit
import urllib.request
from uuid import UUID


BODY_LIMIT = 262144
TOTAL_LIMIT = 1048576
CONFIG_LIMIT = 65536
NODE_LIMIT = 4096
DEPTH_LIMIT = 16
REPORT_LIMIT = 16384
ORIGINS = {'prometheus_base_url': 'http://127.0.0.1:18175',
           'exporter_base_url': 'http://127.0.0.1:18178'}
UUID_FIELDS = ('server_a_id', 'deployment_a_id', 'server_b_id', 'deployment_b_id',
               'node_b_id', 'install_operation_b_id', 'project_id', 'source_revision_id')
ID_FIELDS = ('prometheus_container_id', 'exporter_container_id')
HASH_FIELDS = ('inventory_digest', 'effective_checksum',
               'prometheus_config_sha256', 'exporter_config_sha256')
PATH_FIELDS = ('prometheus_config_path', 'exporter_config_path')
IMAGE_FIELDS = ('prometheus_image', 'exporter_image')
INPUT_FIELDS = {'bindings', 'prometheus_base_url', 'exporter_base_url', 'target_url',
                'module', 'job', 'instance', 'declared_module', 'declared_job',
                'max_age_seconds'}
REASONS = {'observed', 'probe_down', 'probe_failed', 'invalid_inputs',
           'unsupported_prerequisite', 'association_mismatch', 'ambiguous_target',
           'ambiguous_series', 'config_mismatch', 'stale_observation', 'clock_invalid',
           'response_unavailable', 'response_invalid', 'response_limit_exceeded',
           'collection_deadline', 'report_limit_exceeded'}
JSON_TOKEN = re.compile(r'\s*("(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"'
                        r'|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?'
                        r'|true|false|null|[{}\[\],:])')


class Refusal(Exception):
    """Expose only an approved reason, never a native exception or body."""

    def __init__(self, reason):
        self.reason = reason


def require(condition, reason='response_invalid'):
    """Refuse before using an unqualified fact."""
    if not condition:
        raise Refusal(reason)


def unique_object(pairs):
    """Reject duplicate JSON keys instead of choosing one value."""
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def strict_json(raw):
    """Bound lexical nodes/depth before allocating the JSON object tree."""
    text = raw.decode('utf-8') if isinstance(raw, bytes) else raw
    position = depth = nodes = 0
    while position < len(text):
        token = JSON_TOKEN.match(text, position)
        if token is None and text[position:].isspace():
            break
        require(token is not None)
        value = token.group(1)
        position = token.end()
        if value in ('}', ']'):
            depth -= 1
        elif value in ('{', '['):
            depth += 1
        if value not in (',', ':', '}', ']'):
            nodes += 1
        require(0 <= depth <= DEPTH_LIMIT and nodes <= NODE_LIMIT,
                'response_limit_exceeded')
    require(depth == 0)
    return json.loads(text, object_pairs_hook=unique_object, parse_float=finite_number,
                      parse_constant=lambda value: require(False))


def strict_yaml(text):
    """Require safe bounded YAML with no aliases, anchors, merges or key ambiguity."""
    require(isinstance(text, str))
    require(len(text.encode('utf-8')) <= CONFIG_LIMIT, 'response_limit_exceeded')
    try:
        import yaml
    except ImportError as error:
        raise Refusal('unsupported_prerequisite') from error

    class LoadedConfig(yaml.SafeLoader):
        def __init__(self, stream):
            super().__init__(stream)
            self.nodes = self.depth = 0

        def compose_node(self, parent, index):
            require(not self.check_event(yaml.AliasEvent))
            require(getattr(self.peek_event(), 'anchor', None) is None)
            self.nodes += 1
            self.depth += 1
            require(self.nodes <= NODE_LIMIT and self.depth <= DEPTH_LIMIT,
                    'response_limit_exceeded')
            try:
                return super().compose_node(parent, index)
            finally:
                self.depth -= 1

        def construct_mapping(self, node, deep=False):
            require(isinstance(node, yaml.MappingNode))
            result = {}
            for key_node, value_node in node.value:
                require(key_node.tag == 'tag:yaml.org,2002:str')
                key = self.construct_object(key_node, deep=deep)
                require(key != '<<' and key not in result)
                result[key] = self.construct_object(value_node, deep=deep)
            return result

        def construct_object(self, node, deep=False):
            value = super().construct_object(node, deep=deep)
            require(type(value) is not float or math.isfinite(value))
            return value

    return yaml.load(text, Loader=LoadedConfig)


def digest(value):
    """Validate canonical SHA-256 spelling."""
    return isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value) is not None


def exact(value, expected):
    """Keep boolean and numeric meanings distinct in declared semantic objects."""
    return json.dumps(value, sort_keys=True, allow_nan=False) == json.dumps(
        expected, sort_keys=True, allow_nan=False)


def module_projection(name):
    """Describe this journey's explicitly frozen module, not a deployment default."""
    return {'name': name, 'prober': 'http', 'timeout': '8s', 'http': {
        'method': 'GET', 'valid_status_codes': [200], 'follow_redirects': False,
        'fail_if_not_ssl': True, 'preferred_ip_protocol': 'ip4',
        'ip_protocol_fallback': False, 'tls_config': {'insecure_skip_verify': False}}}


def job_projection(job, module, target):
    """Describe the admitted ordered relabel association."""
    return {'job_name': job, 'scrape_interval': '15s', 'scrape_timeout': '10s',
            'metrics_path': '/probe', 'scheme': 'http', 'params': {'module': [module]},
            'static_configs': [{'targets': [target], 'labels': {'module': module}}],
            'relabel_configs': [
                {'source_labels': ['__address__'], 'target_label': '__param_target'},
                {'source_labels': ['__param_target'], 'target_label': 'instance'},
                {'target_label': '__address__', 'replacement': 'blackbox:9115'}]}


def validate_inputs(args):
    """Admit only safe declared bindings and the pinned loopback journey profile."""
    require(type(args) is dict and set(args) == INPUT_FIELDS, 'invalid_inputs')
    bindings = args['bindings']
    fields = set(UUID_FIELDS + ID_FIELDS + HASH_FIELDS + PATH_FIELDS + IMAGE_FIELDS)
    require(type(bindings) is dict and set(bindings) == fields, 'invalid_inputs')
    for key in UUID_FIELDS:
        value = bindings[key]
        require(isinstance(value, str) and str(UUID(value)) == value, 'invalid_inputs')
    for key in ID_FIELDS + HASH_FIELDS:
        require(digest(bindings[key]), 'invalid_inputs')
    for key in IMAGE_FIELDS:
        value = bindings[key]
        require(isinstance(value, str) and len(value) <= 256
                and re.fullmatch(r'[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}', value),
                'invalid_inputs')
    for key in PATH_FIELDS:
        value = bindings[key]
        require(isinstance(value, str) and len(value.encode('utf-8')) <= 256
                and value not in ('', '.') and not value.startswith('/')
                and PurePosixPath(value).as_posix() == value
                and '..' not in PurePosixPath(value).parts
                and not any(ord(char) < 32 or char == '\\' for char in value),
                'invalid_inputs')
    require(all(args[key] == value for key, value in ORIGINS.items()), 'invalid_inputs')
    target = args['target_url']
    require(isinstance(target, str) and len(target.encode('utf-8')) <= 2048,
            'invalid_inputs')
    url = urlsplit(target)
    require(url.scheme == 'https' and url.hostname and url.netloc == url.hostname
            and not url.username and not url.password and not url.query and not url.fragment
            and url.path == '/wp-admin/install.php'
            and re.fullmatch(r'[a-z0-9.-]+', url.hostname)
            and not any(ord(char) < 33 or ord(char) > 126 for char in target), 'invalid_inputs')
    require(args['module'] == args['job'] == 'wordpress_https'
            and args['instance'] == target, 'invalid_inputs')
    age = args['max_age_seconds']
    require(type(age) is int and 1 <= age <= 60, 'invalid_inputs')
    require(exact(args['declared_module'], module_projection(args['module']))
            and exact(args['declared_job'], job_projection(args['job'], args['module'], target)),
            'invalid_inputs')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never move an observation away from its exact origin."""

    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def request_worker(url, limit):
    """Read bounded HTTP in a process whose parent enforces complete wall closure."""
    try:
        require(type(limit) is int and 0 < limit <= BODY_LIMIT)
        parsed = urlsplit(url)
        require(parsed.scheme == 'http' and parsed.hostname == '127.0.0.1'
                and parsed.port in (18175, 18178) and not parsed.username
                and not parsed.password and not parsed.fragment)
        require(parsed.path in ('/api/v1/targets', '/api/v1/status/config',
                                '/api/v1/query', '/config'))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        request = urllib.request.Request(url, headers={'Accept-Encoding': 'identity'})
        with opener.open(request, timeout=10) as response:
            require(response.status == 200, 'response_unavailable')
            require(response.headers.get('Content-Encoding', 'identity') == 'identity')
            lengths = response.headers.get_all('Content-Length', [])
            require(len(lengths) <= 1)
            if lengths:
                require(re.fullmatch(r'[0-9]+', lengths[0]) is not None)
                require(int(lengths[0]) <= limit, 'response_limit_exceeded')
            body = bytearray()
            while True:
                chunk = response.read1(min(16384, limit + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                require(len(body) <= limit, 'response_limit_exceeded')
            require(not lengths or len(body) == int(lengths[0]))
        sys.stdout.buffer.write(b'ok\n' + body)
    except Refusal as error:
        sys.stdout.buffer.write(error.reason.encode('ascii') + b'\n')
    except Exception:
        sys.stdout.buffer.write(b'response_unavailable\n')


class Requests:
    """Own only the five fixed requests and their finite aggregate budget."""

    def __init__(self):
        self.deadline = time.monotonic() + 60
        self.bytes = self.calls = 0

    def get(self, url):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0 and self.calls < 5, 'collection_deadline')
        limit = min(BODY_LIMIT, TOTAL_LIMIT - self.bytes)
        require(limit > 0, 'response_limit_exceeded')
        self.calls += 1
        try:
            result = subprocess.run(
                [sys.executable, '-I', os.path.abspath(__file__), '--http', url, str(limit)],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL, timeout=min(10, remaining), check=False,
                env={'PATH': os.defpath, 'PYTHONDONTWRITEBYTECODE': '1'})
        except subprocess.TimeoutExpired as error:
            raise Refusal('collection_deadline') from error
        require(result.returncode == 0 and len(result.stdout) <= limit + 80)
        code, separator, body = result.stdout.partition(b'\n')
        require(separator)
        if code != b'ok':
            reason = code.decode('ascii')
            raise Refusal(reason if reason in REASONS else 'response_unavailable')
        self.bytes += len(body)
        require(self.bytes <= TOTAL_LIMIT, 'response_limit_exceeded')
        require(time.monotonic() <= self.deadline, 'collection_deadline')
        return body


def loaded_module(config, args):
    """Normalize only measured v0.27.0 marshaled zeros; reject other additions."""
    require(type(config) is dict and set(config) == {'modules'}, 'config_mismatch')
    modules = config['modules']
    require(type(modules) is dict and len(modules) <= 256, 'response_limit_exceeded')
    require(args['module'] in modules, 'config_mismatch')
    module = modules[args['module']]
    require(type(module) is dict and set(module) <= {'prober', 'timeout', 'http',
                                                  'tcp', 'icmp', 'dns', 'grpc'},
            'config_mismatch')
    http = module.get('http')
    allowed = set(args['declared_module']['http']) | {'enable_http2'}
    require(type(http) is dict and set(http) <= allowed, 'config_mismatch')
    normalized = dict(http)
    require('enable_http2' not in normalized or normalized['enable_http2'] is True,
            'config_mismatch')
    normalized.pop('enable_http2', None)
    normalized.setdefault('ip_protocol_fallback', False)
    normalized.setdefault('tls_config', {})
    tls = normalized['tls_config']
    require(type(tls) is dict and set(tls) <= {'insecure_skip_verify'}, 'config_mismatch')
    normalized['tls_config'] = {'insecure_skip_verify': tls.get('insecure_skip_verify', False)}
    require(exact({'name': args['module'], 'prober': module.get('prober'),
                   'timeout': module.get('timeout'), 'http': normalized},
                  args['declared_module']),
            'config_mismatch')


def loaded_job(config, args):
    """Require exact ordered relabel semantics and qualified native default additions."""
    require(type(config) is dict, 'config_mismatch')
    jobs = config.get('scrape_configs')
    require(type(jobs) is list and len(jobs) <= 256, 'response_limit_exceeded')
    matches = [job for job in jobs if type(job) is dict and job.get('job_name') == args['job']]
    require(len(matches) == 1, 'config_mismatch')
    job = dict(matches[0])
    defaults = {
        'honor_timestamps': True, 'track_timestamps_staleness': False,
        'scrape_protocols': ['OpenMetricsText1.0.0', 'OpenMetricsText0.0.1',
                             'PrometheusText1.0.0', 'PrometheusText0.0.4'],
        'scrape_native_histograms': False, 'always_scrape_classic_histograms': False,
        'convert_classic_histograms_to_nhcb': False,
        'metric_name_validation_scheme': 'utf8', 'metric_name_escaping_scheme': 'allow-utf-8',
        'enable_compression': True, 'enable_http2': True, 'follow_redirects': True,
    }
    for key, value in defaults.items():
        if key in job:
            require(type(job[key]) is type(value) and job[key] == value, 'config_mismatch')
            del job[key]
    rules = job.get('relabel_configs')
    expected = args['declared_job']['relabel_configs']
    require(type(rules) is list and len(rules) == len(expected), 'config_mismatch')
    normalized = []
    for rule, wanted in zip(rules, expected):
        require(type(rule) is dict and set(rule) <= {
            'source_labels', 'target_label', 'replacement', 'action', 'regex', 'separator'},
            'config_mismatch')
        require(rule.get('action', 'replace') == 'replace'
                and rule.get('regex', '(.*)') == '(.*)'
                and rule.get('separator', ';') == ';', 'config_mismatch')
        value = {key: item for key, item in rule.items()
                 if key not in ('action', 'regex', 'separator')}
        if 'replacement' not in wanted:
            require(value.get('replacement', '$1') == '$1', 'config_mismatch')
            value.pop('replacement', None)
        normalized.append(value)
    job['relabel_configs'] = normalized
    require(exact(job, args['declared_job']), 'config_mismatch')


def api_data(raw):
    """Require successful nonpartial API data without exposing error detail."""
    result = strict_json(raw)
    require(type(result) is dict and result.get('status') == 'success'
            and not result.get('warnings') and not result.get('infos'))
    return result['data']


def finite_number(value):
    """Reject booleans, invalid numeric strings and nonfinite native values."""
    require(type(value) in (str, int, float))
    number = float(value)
    require(math.isfinite(number))
    return number


def series(data, labels, metric_name):
    """Accept one exact label-qualified vector, with metric name checked separately."""
    require(type(data) is dict and data.get('resultType') == 'vector')
    rows = data.get('result')
    require(type(rows) is list and len(rows) == 1, 'ambiguous_series')
    row = rows[0]
    require(type(row) is dict and set(row) == {'metric', 'value'})
    expected = dict(labels)
    if metric_name:
        expected['__name__'] = metric_name
    require(row['metric'] == expected, 'association_mismatch')
    require(type(row['value']) is list and len(row['value']) == 2)
    return finite_number(row['value'][0]), finite_number(row['value'][1])


def blank_report():
    """Keep unavailable facts null rather than implying healthy or absent state."""
    return {'outcome': 'unknown', 'reason': 'invalid_inputs',
            'collection_origin': 'host-on-b', 'probe_origin': 'workload-on-b',
            **{key: None for key in (
                'declared_server_b_id', 'declared_prometheus_container_id',
                'declared_exporter_container_id', 'job', 'module', 'instance', 'target_url',
                'loaded_job_matches', 'loaded_module_matches', 'target_healthy',
                'last_error_empty', 'probe_success', 'native_start', 'native_end',
                'evaluation_time', 'last_scrape', 'sample_time', 'max_age_seconds')}}


def collect(args, requests=None):
    """Observe only the frozen association, then qualify its underlying freshness."""
    report = blank_report()
    start = time.time()
    monotonic = time.monotonic()
    try:
        validate_inputs(args)
        strict_yaml('modules: {}')
        bindings = args['bindings']
        report.update({
            'declared_server_b_id': bindings['server_b_id'],
            'declared_prometheus_container_id': bindings['prometheus_container_id'],
            'declared_exporter_container_id': bindings['exporter_container_id'],
            **{key: args[key] for key in ('job', 'module', 'instance', 'target_url',
                                        'max_age_seconds')},
            'native_start': start, 'evaluation_time': start})
        requests = requests or Requests()
        prometheus = args['prometheus_base_url']
        targets = api_data(requests.get(prometheus + '/api/v1/targets?state=active'))
        config = api_data(requests.get(prometheus + '/api/v1/status/config'))
        loaded_job(strict_yaml(config['yaml']), args)
        report['loaded_job_matches'] = True
        loaded_module(strict_yaml(requests.get(args['exporter_base_url'] + '/config')
                                  .decode('utf-8')), args)
        report['loaded_module_matches'] = True
        labels = {key: args[key] for key in ('job', 'instance', 'module')}
        require(type(targets) is dict and type(targets.get('activeTargets')) is list)
        active = targets['activeTargets']
        require(len(active) <= 256, 'response_limit_exceeded')
        matches = [row for row in active if type(row) is dict and row.get('labels') == labels]
        require(len(matches) == 1, 'ambiguous_target')
        target = matches[0]
        scrape = urlsplit(target.get('scrapeUrl', ''))
        require(target.get('scrapePool') == args['job'] and scrape.scheme == 'http'
                and scrape.netloc == 'blackbox:9115' and scrape.path == '/probe'
                and scrape.query == urlencode({'module': args['module'], 'target': args['target_url']})
                and not scrape.fragment, 'association_mismatch')
        require(target.get('health') in ('up', 'down')
                and type(target.get('lastError')) is str)
        report['target_healthy'] = target['health'] == 'up'
        report['last_error_empty'] = target['lastError'] == ''
        stamp = target['lastScrape']
        require(isinstance(stamp, str) and stamp.endswith('Z'))
        report['last_scrape'] = datetime.fromisoformat(stamp[:-1] + '+00:00').timestamp()
        selector = 'probe_success{' + ','.join(
            key + '=' + json.dumps(value, ensure_ascii=False) for key, value in labels.items()) + '}'
        facts = []
        for query in (selector, 'timestamp(' + selector + ')'):
            params = urlencode({'query': query, 'time': format(start, '.6f')})
            facts.append(api_data(requests.get(prometheus + '/api/v1/query?' + params)))
        probe_time, probe = series(facts[0], labels, 'probe_success')
        timestamp_time, sample = series(facts[1], labels, None)
        require(abs(probe_time - start) <= 0.001 and abs(timestamp_time - start) <= 0.001,
                'clock_invalid')
        require(probe in (0.0, 1.0))
        report['probe_success'] = probe
        report['sample_time'] = sample
        for observed in (sample, report['last_scrape']):
            require(0 <= start - observed <= args['max_age_seconds'], 'stale_observation')
        elapsed = time.monotonic() - monotonic
        end = time.time()
        require(abs((end - start) - elapsed) <= 1 and elapsed <= 60, 'clock_invalid')
        if not report['target_healthy']:
            report.update(outcome='failed', reason='probe_down')
        elif not report['last_error_empty']:
            raise Refusal('association_mismatch')
        elif probe == 0:
            report.update(outcome='failed', reason='probe_failed')
        else:
            report.update(outcome='succeeded', reason='observed')
    except Refusal as error:
        report.update(outcome='unknown', reason=error.reason)
    except Exception:
        report.update(outcome='unknown', reason='response_invalid' if report['native_start'] else 'invalid_inputs')
    report['native_end'] = time.time()
    if abs((report['native_end'] - start) - (time.monotonic() - monotonic)) > 1:
        report.update(outcome='unknown', reason='clock_invalid')
    return report


def emit(report):
    """Emit one complete bounded UTF-8 object, never clip a surviving prefix."""
    encoded = (json.dumps(report, ensure_ascii=True, allow_nan=False,
                          separators=(',', ':')) + '\n').encode('utf-8')
    if len(encoded) > REPORT_LIMIT:
        report = blank_report()
        report['reason'] = 'report_limit_exceeded'
        encoded = (json.dumps(report, separators=(',', ':')) + '\n').encode('ascii')
    sys.stdout.buffer.write(encoded)


def main():
    """Keep worker transport private and public invocation failures bounded."""
    if len(sys.argv) == 4 and sys.argv[1] == '--http':
        request_worker(sys.argv[2], int(sys.argv[3]))
        return 0
    try:
        require(len(sys.argv) == 2, 'invalid_inputs')
        require(len(sys.argv[1]) <= 131072, 'invalid_inputs')
        args = strict_json(base64.b64decode(sys.argv[1], validate=True))
    except Exception:
        emit(blank_report())
        return 0
    emit(collect(args))
    return 0


if __name__ == '__main__':
    sys.exit(main())
