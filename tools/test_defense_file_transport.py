"""Process restart coverage for the defender's on-disk Node transport."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from defense_file_receipt import read_committed_record


NODE = shutil.which('node')
TRANSPORT = Path(__file__).with_name('defense_file_transport.mjs')
INVOKE = """
const [transport, method, queue, ...args] = process.argv.slice(1);
const worker = await import(transport);
const result = await worker[method](queue, ...args.map(value => JSON.parse(value)));
console.log(JSON.stringify(result));
"""


@unittest.skipUnless(NODE, 'Node is required for the defender transport')
class NodeTransportRestartTests(unittest.TestCase):
    def test_new_process_uses_committed_queue_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            product = root / 'tools'
            product.mkdir()
            transport = Path(shutil.copyfile(TRANSPORT, product / TRANSPORT.name))
            queue = root / 'artifacts/restart/queue'
            queue.mkdir(parents=True)
            identity = {
                'agent_id': '/root/restart_test', 'model': 'gpt-6-luna',
                'reasoning_effort': 'low',
            }
            (queue / 'worker-configuration.json').write_text(json.dumps(identity), encoding='utf-8')

            def invoke(method, argument):
                result = subprocess.run(
                    [NODE, '--input-type=module', '-e', INVOKE, transport.as_uri(),
                     method, str(queue), json.dumps(argument)],
                    text=True, encoding='utf-8', capture_output=True, timeout=5, check=True,
                )
                return json.loads(result.stdout)

            self.assertEqual(invoke('start', 0), {'status': 'PENDING', 'call': 1})
            first_input = b'first transport fixture'
            (queue / 'call-01.input.txt').write_bytes(first_input)
            (queue / 'call-02.input.txt').write_text('second transport fixture', encoding='utf-8')
            first = invoke('resume', 0)
            self.assertEqual(first['status'], 'INPUT')
            self.assertEqual(first['input'], first_input.decode())
            self.assertEqual(first['input_sha256'], hashlib.sha256(first_input).hexdigest())

            raw = '{ "transport_fixture": 1 }'
            envelope = {
                'call': 1, 'input_sha256': first['input_sha256'], 'raw_response': raw,
            }
            self.assertEqual(invoke('commit', envelope), {
                'status': 'COMMITTED', 'call': 1, 'input_sha256': first['input_sha256'],
            })
            response = queue / 'call-01.response.json'
            marker = response.with_suffix('.json.complete')
            # Reproduce a reset after the durable marker but before the peer
            # sees the response under its conventional filename.
            response.rename(queue / 'simulated-interrupted-response.json')
            self.assertIsNone(read_committed_record(response))
            second = invoke('resume', 0)
            self.assertEqual(second['status'], 'INPUT')
            self.assertEqual(second['call'], 2)
            self.assertEqual(second['input_sha256'], invoke('next', 2)['input_sha256'])

            saved = read_committed_record(response)
            self.assertEqual(marker.read_bytes(), response.read_bytes())
            self.assertEqual(saved['raw_response'], raw)
            self.assertEqual(saved['input_sha256'], first['input_sha256'])
            self.assertEqual({key: saved[key] for key in identity}, identity)
            with self.assertRaises(subprocess.CalledProcessError) as error:
                invoke('commit', envelope)
            self.assertIn('cannot be overwritten', error.exception.stderr)
            with self.assertRaises(subprocess.CalledProcessError) as error:
                invoke('resume', 8.1)
            self.assertIn('bounded call/wait required', error.exception.stderr)


class ReceiptTests(unittest.TestCase):
    def test_uncommitted_and_inconsistent_records_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            record = Path(temporary) / 'response.json'
            record.write_text('{"raw_response":"original"}', encoding='utf-8')
            self.assertIsNone(read_committed_record(record))
            marker = record.with_suffix('.json.complete')
            marker.write_text('{"raw_response":"different"}', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'completion marker differs'):
                read_committed_record(record)


if __name__ == '__main__':
    unittest.main()
