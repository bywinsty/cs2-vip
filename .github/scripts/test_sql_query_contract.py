#!/usr/bin/env python3
"""Contract checks for failure-aware SQLMM queries outside migration."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class SQLQueryContractTests(unittest.TestCase):
    def test_production_queries_use_failure_aware_adapter(self):
        source = (ROOT / "vip.cpp").read_text(encoding="utf-8")
        self.assertIn("void QueryChecked(", source)
        self.assertIn("Transaction{std::vector<std::string>{query}}", source)
        self.assertIn("SQLMM returned no query result", source)
        self.assertIn("[VIP] SQL query failed", source)
        self.assertNotIn("g_pConnection->Query(", source)

    def test_authorization_failure_notifies_client(self):
        source = (ROOT / "vip.cpp").read_text(encoding="utf-8")
        self.assertGreaterEqual(source.count("Authorization query failed"), 1)
        self.assertGreaterEqual(source.count("Call_VIP_OnClientLoaded(iSlot, false)"), 2)


if __name__ == "__main__":
    unittest.main()
