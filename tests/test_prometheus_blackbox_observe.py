"""Production collector/emitter with explicit HTTP and script-output substitutions."""

import copy
from datetime import datetime, timezone
import importlib.util
import io
import json
import multiprocessing
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlencode, urlsplit

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'catalog/ansible/scripts/prometheus_blackbox_observe.py'
PLAY = ROOT / 'catalog/ansible/playbooks/prometheus_blackbox_observe.yml'
SPEC = importlib.util.spec_from_file_location('production_observer', SCRIPT)
observer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observer)
TARGET = 'https://synthetic.example.invalid/wp-admin/install.php'


def inputs():
    """Build new synthetic declarations, never actual admitted B identities."""
    bindings = {key: '00000000-0000-4000-8000-000000000001' for key in observer.UUID_FIELDS}
    bindings.update({key: 'a' * 64 for key in observer.ID_FIELDS + observer.HASH_FIELDS})
    bindings.update({key: 'config/' + key + '.yml' for key in observer.PATH_FIELDS})
    bindings.update({key: 'example.invalid/image@sha256:' + 'b' * 64
                     for key in observer.IMAGE_FIELDS})
    return {'bindings': bindings, **observer.ORIGINS, 'target_url': TARGET,
            'module': 'wordpress_https', 'job': 'wordpress_https', 'instance': TARGET,
            'declared_module': observer.module_projection('wordpress_https'),
            'declared_job': observer.job_projection('wordpress_https', 'wordpress_https', TARGET),
            'max_age_seconds': 60}


class Responses:
    """Five explicit response fixtures; no native service or resource authority."""

    def __init__(self, case):
        self.case = case
        self.calls = []

    def get(self, url):
        self.calls.append(url)
        args = inputs()
        labels = {key: args[key] for key in ('job', 'instance', 'module')}
        parsed = urlsplit(url)
        if self.case == 'unavailable':
            raise observer.Refusal('response_unavailable')
        if parsed.path == '/api/v1/status/config':
            job = copy.deepcopy(args['declared_job'])
            for rule in job['relabel_configs']:
                rule.update(action='replace', separator=';')
            job['honor_timestamps'] = True
            if self.case == 'job_drift':
                job['relabel_configs'][2]['replacement'] = 'foreign:9115'
            return json.dumps({'status': 'success', 'data': {
                'yaml': yaml.safe_dump({'scrape_configs': [job]})}}).encode()
        if parsed.path == '/config':
            module = copy.deepcopy(args['declared_module'])
            module.pop('name')
            module['http'].pop('ip_protocol_fallback')
            module['http'].pop('tls_config')
            module['http']['enable_http2'] = True
            if self.case == 'module_drift':
                module['http']['headers'] = {'Authorization': 'PRIVATE_HEADER_MARKER'}
            return yaml.safe_dump({'modules': {'wordpress_https': module}}).encode()
        if parsed.path == '/api/v1/targets':
            target = {'labels': labels, 'scrapePool': args['job'],
                      'scrapeUrl': 'http://blackbox:9115/probe?' + urlencode({
                          'module': args['module'], 'target': TARGET}),
                      'health': 'down' if self.case == 'down' else 'up',
                      'lastError': 'PRIVATE_ERROR_MARKER' if self.case == 'down' else '',
                      'lastScrape': datetime.fromtimestamp(time.time() - 3, timezone.utc)
                          .isoformat().replace('+00:00', 'Z')}
            if self.case == 'target_label':
                target['labels']['extra'] = 'PRIVATE_LABEL_MARKER'
            rows = [target, target] if self.case == 'duplicate_target' else [target]
            return json.dumps({'status': 'success', 'data': {'activeTargets': rows}}).encode()
        query = parse_qs(parsed.query)
        evaluation = float(query['time'][0])
        stamp = query['query'][0].startswith('timestamp(')
        metric = dict(labels)
        if not stamp or self.case == 'timestamp_name':
            metric['__name__'] = 'probe_success'
        sample = evaluation - (61 if self.case == 'stale' else 3)
        if self.case == 'future':
            sample = evaluation + 1
        value = sample if stamp else (0 if self.case == 'zero' else 1)
        row = {'metric': metric, 'value': [evaluation, str(value)]}
        rows = [row, row] if self.case == 'duplicate_series' else [row]
        return json.dumps({'status': 'success', 'data': {
            'resultType': 'vector', 'result': rows}}).encode()


def serve_once(case, ready):
    """Own one loopback socket inside the network-disabled test container."""
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('127.0.0.1', 18175))
        server.listen(1)
        ready.send(True)
        with server.accept()[0] as connection:
            connection.recv(4096)
            if case == 'slow':
                time.sleep(30)
            elif case == 'length':
                connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 262145\r\n\r\n')
            elif case == 'compressed':
                connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n'
                                   b'Content-Length: 1\r\n\r\nx')
            elif case == 'duplicate_length':
                connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n'
                                   b'Content-Length: 2\r\n\r\nx')
            else:
                try:
                    connection.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n'
                                       + b'x' * 262145)
                except ConnectionError:
                    pass


class PrometheusBlackboxObserveTests(unittest.TestCase):
    def test_association_configuration_freshness_and_truthful_outcomes(self):
        expected = {
            'healthy': ('succeeded', 'observed'), 'down': ('failed', 'probe_down'),
            'zero': ('failed', 'probe_failed'), 'stale': ('unknown', 'stale_observation'),
            'future': ('unknown', 'stale_observation'),
            'target_label': ('unknown', 'ambiguous_target'),
            'duplicate_target': ('unknown', 'ambiguous_target'),
            'duplicate_series': ('unknown', 'ambiguous_series'),
            'timestamp_name': ('unknown', 'association_mismatch'),
            'job_drift': ('unknown', 'config_mismatch'),
            'module_drift': ('unknown', 'config_mismatch'),
            'unavailable': ('unknown', 'response_unavailable'),
        }
        for case, outcome in expected.items():
            with self.subTest(case=case):
                transport = Responses(case)
                report = observer.collect(inputs(), transport)
                self.assertEqual((report['outcome'], report['reason']), outcome)
                self.assertEqual(set(report), set(observer.blank_report()))
                self.assertNotIn('PRIVATE_', json.dumps(report))
                self.assertLessEqual(len(transport.calls), 5)
                if case in ('healthy', 'zero', 'down'):
                    self.assertEqual(len(transport.calls), 5)
                    self.assertEqual(report['probe_success'], 0 if case == 'zero' else 1)
                    self.assertAlmostEqual(report['evaluation_time'] - report['sample_time'], 3,
                                           delta=0.001)
                    self.assertTrue(report['loaded_job_matches'])
                    self.assertTrue(report['loaded_module_matches'])

    def test_strict_inputs_parsers_and_finite_budgets(self):
        for field, value in (('max_age_seconds', True), ('max_age_seconds', 60.0),
                             ('prometheus_base_url', 'http://foreign.invalid'),
                             ('target_url', TARGET + '?private=PRIVATE_QUERY_MARKER')):
            with self.subTest(field=field, value=value):
                args = inputs()
                args[field] = value
                transport = Responses('healthy')
                report = observer.collect(args, transport)
                self.assertEqual(report['reason'], 'invalid_inputs')
                self.assertEqual(transport.calls, [])
                self.assertNotIn('PRIVATE_', json.dumps(report))
        for raw in (b'{"a":1,"a":2}', b'NaN', b'1e309', b'\xff',
                    b'[' * 17 + b'0' + b']' * 17, b'[' + b'0,' * 4096 + b'0]'):
            with self.subTest(json=raw[:30]):
                with self.assertRaises((observer.Refusal, ValueError, UnicodeError)):
                    observer.strict_json(raw)
        for raw in ('a: 1\na: 2', 'a: &x 1\nb: *x', 'a: !!python/object:x {}',
                    '1: value', 'a: {<<: {b: 1}}', 'a: .inf', 'a: .nan',
                    'a: [' * 17 + '0' + ']' * 17, 'a: ' + 'x' * 65536):
            with self.subTest(yaml=raw[:30]):
                with self.assertRaises((observer.Refusal, yaml.YAMLError)):
                    observer.strict_yaml(raw)
        original_import = __import__

        def missing_yaml(name, *args, **kwargs):
            if name == 'yaml':
                raise ImportError('synthetic unavailable dependency')
            return original_import(name, *args, **kwargs)

        with mock.patch('builtins.__import__', side_effect=missing_yaml):
            transport = Responses('healthy')
            self.assertEqual(observer.collect(inputs(), transport)['reason'],
                             'unsupported_prerequisite')
            self.assertEqual(transport.calls, [])
        response = subprocess.CompletedProcess([], 0, b'ok\n' + b'x' * observer.BODY_LIMIT)
        with mock.patch.object(observer.subprocess, 'run', return_value=response) as run:
            requests = observer.Requests()
            for unused in range(4):
                self.assertEqual(len(requests.get('synthetic fixed response')), observer.BODY_LIMIT)
            with self.assertRaises(observer.Refusal) as error:
                requests.get('no further read')
            self.assertEqual(error.exception.reason, 'response_limit_exceeded')
            self.assertEqual(run.call_count, 4)

    def test_reduced_public_output_contract_and_emit_cap(self):
        fields = {'outcome', 'reason', 'collection_origin', 'probe_origin',
                  'loaded_job_matches', 'loaded_module_matches', 'target_healthy',
                  'last_error_empty', 'probe_success', 'native_start', 'native_end',
                  'evaluation_time', 'last_scrape', 'sample_time', 'max_age_seconds'}
        removed = {'declared_server_b_id', 'declared_prometheus_container_id',
                   'declared_exporter_container_id', 'job', 'module', 'instance', 'target_url'}
        transport = Responses('healthy')
        healthy = observer.collect(inputs(), transport)
        self.assertEqual((healthy['outcome'], healthy['reason']), ('succeeded', 'observed'))
        self.assertEqual(len(transport.calls), 5)
        for report in (observer.blank_report(), healthy):
            with self.subTest(outcome=report['outcome']):
                output = io.BytesIO()
                with mock.patch.object(observer.sys, 'stdout', type('Sink', (), {'buffer': output})()):
                    observer.emit(report)
                wire = output.getvalue()
                emitted = json.loads(wire)
                self.assertEqual(set(emitted), fields)
                self.assertFalse(set(emitted) & removed)
                self.assertTrue(wire.isascii())
                self.assertEqual(wire.count(b'\n'), 1)
                self.assertLessEqual(len(wire), 16384)
        output = io.BytesIO()
        with mock.patch.object(observer.sys, 'stdout', type('Sink', (), {'buffer': output})()):
            report = observer.blank_report()
            report['collection_origin'] = 'x' * 16384
            observer.emit(report)
        self.assertLessEqual(len(output.getvalue()), 16384)
        self.assertEqual(json.loads(output.getvalue()), {
            **observer.blank_report(), 'reason': 'report_limit_exceeded'})

    def test_actual_worker_timeout_and_read_limits_close_owned_processes(self):
        expected = {'slow': 'collection_deadline', 'length': 'response_limit_exceeded',
                    'streamed': 'response_limit_exceeded', 'compressed': 'response_invalid',
                    'duplicate_length': 'response_invalid'}
        for case, reason in expected.items():
            with self.subTest(case=case):
                parent, child = multiprocessing.Pipe()
                server = multiprocessing.Process(target=serve_once, args=(case, child))
                owned = []
                original = subprocess.Popen

                class ObservedProcess(original):
                    def __init__(self, *args, **kwargs):
                        super().__init__(*args, **kwargs)
                        owned.append(self)

                server.start()
                start = time.monotonic()
                try:
                    self.assertTrue(parent.poll(3))
                    self.assertTrue(parent.recv())
                    with mock.patch.object(subprocess, 'Popen', ObservedProcess):
                        with self.assertRaises(observer.Refusal) as error:
                            observer.Requests().get(
                                'http://127.0.0.1:18175/api/v1/targets?state=active')
                    self.assertEqual(error.exception.reason, reason)
                    self.assertLess(time.monotonic() - start, 13)
                    self.assertEqual(len(owned), 1)
                    self.assertIsNotNone(owned[0].returncode)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(owned[0].pid, 0)
                finally:
                    server.terminate()
                    server.join(3)
                    parent.close()
                    child.close()
                self.assertFalse(server.is_alive())

    def test_loaded_play_framing_membership_and_exact_ascii_wire(self):
        cases = ('rc', 'nonobject', 'extra', 'missing', 'truncated', 'multiple',
                 'at_cap', 'over_cap', 'escaped')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                play = yaml.safe_load(PLAY.read_text())
                command = play[0]['tasks'][2]['block'][1]['ansible.builtin.script']
                transport = directory / 'transport.py'
                transport.write_text(
                    'import runpy\nrunpy.run_path(' + repr(str(Path(__file__).resolve()))
                    + ', run_name="__main__")\n')
                command['cmd'] = str(transport) + ' --transport ' + case
                command['executable'] = sys.executable
                invocation = directory / 'play.yml'
                invocation.write_text(yaml.safe_dump(play, sort_keys=False))
                parameters = directory / 'inputs.json'
                parameters.write_text(json.dumps({'opsctl_inputs': {'monitoring_observation': inputs()}}))
                environment = {**os.environ, 'HOME': str(directory), 'ANSIBLE_NOCOLOR': '1',
                               'ANSIBLE_STDOUT_CALLBACK': 'default',
                               'ANSIBLE_LOCAL_TEMP': str(directory / 'local'),
                               'ANSIBLE_REMOTE_TEMP': str(directory / 'remote')}
                result = subprocess.run(
                    ['ansible-playbook', '-i', '127.0.0.1,', '-c', 'local',
                     str(invocation), '-e', '@' + str(parameters)],
                    capture_output=True, text=True, timeout=30, env=environment)
                literal = result.stdout + result.stderr
                print(literal, end='')
                self.assertEqual(result.returncode, 0, literal)
                self.assertNotIn('PRIVATE_', literal)
                messages = []
                for line in result.stdout.splitlines():
                    if '"msg": ' in line:
                        value = json.JSONDecoder().raw_decode(line.split('"msg": ', 1)[1])[0]
                        if isinstance(value, str) and value.startswith('{'):
                            messages.append(value)
                self.assertEqual(len(messages), 1, literal)
                wire = messages[0]
                self.assertTrue(wire.isascii())
                self.assertLessEqual(len(wire.encode('ascii')) + 1, 16384)
                report = json.loads(wire)
                self.assertEqual(set(report), set(observer.blank_report()))
                self.assertEqual(report['outcome'], 'unknown')
                self.assertEqual(report['reason'], 'response_invalid' if case == 'at_cap'
                                 else 'response_unavailable')
                if case == 'at_cap':
                    self.assertEqual(len(wire) + 1, 16384)


def transport_output(case):
    """Padding is malformed-output framing evidence, not semantic qualification."""
    report = observer.blank_report()
    report['reason'] = 'response_invalid'
    if case == 'nonobject':
        report = [report]
    elif case == 'extra':
        report['unexpected'] = 'PRIVATE_EXTRA_MARKER'
    elif case == 'missing':
        del report['loaded_job_matches']
    elif case == 'truncated':
        sys.stdout.write('{"outcome":')
        return 0
    elif case == 'multiple':
        sys.stdout.write('{}\n{}\n')
        return 0
    elif case in ('at_cap', 'over_cap', 'escaped'):
        report['collection_origin'] = ''
        size = len(json.dumps(report, ensure_ascii=True)) + 1
        report['collection_origin'] = ('\u754c' * 2700 if case == 'escaped' else
                                'a' * ((16384 if case == 'at_cap' else 16385) - size))
    print(json.dumps(report, ensure_ascii=False, separators=(',', ':')))
    return 37 if case == 'rc' else 0


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--transport':
        sys.exit(transport_output(sys.argv[2]))
    unittest.main()
