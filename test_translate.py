import tempfile
import unittest
from pathlib import Path

from translate import read_config, translate, write_outputs


class TranslationTests(unittest.TestCase):
    def test_route_distance_and_unresolved_next_hop(self):
        config = """
#
interface Route-Aggregation2
 ip address 192.0.2.1 255.255.255.0
#
 ip route-static default-preference 65
 ip route-static 0.0.0.0 0 192.0.2.2
 ip route-static 198.51.100.0 24 Route-Aggregation2 192.0.2.3 preference 40
 ip route-static 203.0.113.0 24 198.51.100.2
#
"""
        cli, report = translate(config, {"Route-Aggregation2": "port2"}, {}, 900, 900)
        self.assertEqual([route["status"] for route in report["routes"]],
                         ["cli_disabled", "cli_disabled", "manual"])
        self.assertIn('edit 900\n        set status disable', cli)
        self.assertIn("set distance 65", cli)
        self.assertIn("set distance 40", cli)
        self.assertIn('set device "port2"', cli)
        self.assertNotIn("203.0.113.0", cli)

    def test_rule_order_and_fail_closed(self):
        config = """
security-zone name Inside
#
security-zone name Outside
#
security-zone name Local
#
object-group service web
 0 service tcp destination range 8443 8444
#
object-group ip address server
 security-zone Outside
 0 network host address 198.51.100.21
#
security-policy ip
 rule 8 name explicit
  action pass
  source-zone Inside
  destination-zone Outside
  destination-ip server
  service web
 rule 1 name unknown-constraint
  action pass
  source-zone Inside
  destination-zone Outside
  time-range workday
 rule 3 name device-traffic
  action pass
  source-zone Inside
  destination-zone Local
 rule 2 name bound-elsewhere
  action pass
  source-zone Outside
  destination-zone Inside
  destination-ip server
 rule 0 name allow-any
  action pass
 rule 4 name deny-explicit
  action drop
  source-zone Inside
  destination-zone Outside
#
"""
        cli, report = translate(config, {}, {"Inside": "inside", "Outside": "outside"}, 900, 900)
        policies = report["policies"]
        self.assertEqual([p["source_id"] for p in policies], [8, 1, 3, 2, 0, 4])
        self.assertEqual([p["status"] for p in policies],
                         ["cli_disabled", "manual", "manual", "manual", "manual", "cli_disabled"])
        self.assertIn("unsupported rule command", policies[1]["reason"])
        self.assertIn("Local traffic", policies[2]["reason"])
        self.assertIn("zone-bound address", policies[3]["reason"])
        self.assertIn("implicit any-zone", policies[4]["reason"])
        self.assertIn("set tcp-portrange 8443-8444", cli)
        self.assertEqual(cli.count("set status disable"), 2)
        self.assertLess(cli.index("edit 900"), cli.index("edit 905"))
        self.assertIn("set action deny", cli)
        self.assertNotIn("set srcintf \"any\"", cli)

    def test_nat_and_management_data(self):
        config = """
security-zone name Outside
#
object-group service web
 0 service tcp destination eq 8443
#
nat global-policy
 rule name web-dnat
  source-zone Outside
  source-ip host 192.0.2.10
  destination-ip host 192.0.2.20
  service web
  action dnat ip-address 198.51.100.30 local-port 443
  disable
#
local-user fake class manage
 password hash synthetic-credential
#
"""
        cli, report = translate(config, {}, {}, 900, 900)
        rule, = report["nat_rules"]
        self.assertEqual(rule["status"], "nat_review")
        self.assertEqual(rule["mapped_port"], 443)
        self.assertFalse(rule["enabled"])
        self.assertEqual(rule["source_addresses"][0][1], "192.0.2.10")
        self.assertNotIn("config firewall vip", cli)
        self.assertNotIn("synthetic-credential", str(report))

    def test_mixed_encoding_and_exclusive_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            path = folder / "source.cfg"
            path.write_bytes(" description uplink—1\r\n".encode("utf-8")
                             + " description 测试\r\n".encode("gb18030"))
            source, encoding, errors = read_config(path, "auto")
            self.assertEqual(encoding, "mixed UTF-8/GB18030")
            self.assertEqual(errors, [])
            self.assertIn("测试", source)
            first = folder / "out.cli"
            with self.assertRaises(FileExistsError):
                write_outputs(((first, "draft"), (path, "replace")))
            self.assertFalse(first.exists())
            self.assertIn("测试".encode("gb18030"), path.read_bytes())


if __name__ == "__main__":
    unittest.main()
