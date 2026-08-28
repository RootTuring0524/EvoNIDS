import io
import unittest

from app.ingestion.eve import flow_payload, iter_eve_stream


class EveParserTests(unittest.TestCase):
    def test_parses_flow_and_quarantines_bad_lines(self):
        stream = io.StringIO(
            '{"timestamp":"2026-07-19T10:00:00+08:00","flow_id":42,"event_type":"flow",'
            '"src_ip":"192.0.2.10","src_port":51000,"dest_ip":"10.0.0.8","dest_port":445,'
            '"proto":"TCP","flow":{"pkts_toserver":5,"pkts_toclient":2,"bytes_toserver":300,'
            '"bytes_toclient":100,"age":1}}\n'
            "not-json\n"
        )
        failures = []
        records = list(iter_eve_stream(stream, failures))
        self.assertEqual(len(records), 1)
        self.assertEqual(len(failures), 1)
        payload = flow_payload(records[0])
        self.assertEqual(payload["external_id"], "42")
        self.assertEqual(payload["forward_packet_count"], 5)
        self.assertEqual(payload["backward_bytes"], 100)


if __name__ == "__main__":
    unittest.main()

