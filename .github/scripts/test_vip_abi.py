#!/usr/bin/env python3
"""Static ABI contracts for the public VIP interface and factory."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class VipAbiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = (ROOT / "include/vip.h").read_text(encoding="utf-8")
        cls.factory = (ROOT / "vip.cpp").read_text(encoding="utf-8")

    def test_interface_strings_are_versioned(self):
        self.assertIn('#define VIP_INTERFACE_LEGACY "IVIPApi"', self.header)
        self.assertIn('#define VIP_INTERFACE_V2 "IVIPApi002"', self.header)
        self.assertIn("#define VIP_INTERFACE VIP_INTERFACE_V2", self.header)

    def test_v2_extends_frozen_legacy_vtable(self):
        legacy, v2 = self.header.split("class IVIPApi002", 1)
        self.assertIn("class IVIPApi001", legacy)
        self.assertNotIn("VIP_OpenMenu", legacy)
        self.assertIn(": public IVIPApi001", v2)
        self.assertIn("VIP_OpenMenu", v2)
        self.assertIn("using IVIPApi = IVIPApi002", v2)

    def test_factory_serves_both_interfaces(self):
        self.assertIn("strcmp(iface, VIP_INTERFACE_LEGACY)", self.factory)
        self.assertIn("static_cast<IVIPApi001*>(g_pVIPCore)", self.factory)
        self.assertIn("strcmp(iface, VIP_INTERFACE_V2)", self.factory)
        self.assertIn("static_cast<IVIPApi002*>(g_pVIPCore)", self.factory)

    def test_opt_in_runtime_probe_covers_interfaces_and_ready_state(self):
        self.assertIn('std::getenv("VIP_CI_RUNTIME_PROBE")', self.factory)
        self.assertIn('std::getenv("VIP_CI_RUNTIME_NONCE")', self.factory)
        self.assertIn('"[VIP-CI] {\\"event\\":\\"interfaces\\"', self.factory)
        self.assertIn('"[VIP-CI] {\\"event\\":\\"core_ready\\"', self.factory)
        ready = self.factory.index("g_pVIPApi->SetReady(true);")
        probe = self.factory.index("EmitRuntimeReadyProbe();", ready)
        self.assertGreater(probe, ready)

    def test_server_console_probe_writes_nonce_bound_database_evidence(self):
        for required in (
            "RuntimeProbeCommand(const CCommandContext &context",
            "context.GetPlayerSlot().Get() >= 0",
            '"vip_runtime_probe"',
            "FCVAR_SERVER_CAN_EXECUTE",
            "ValidRuntimeNonce",
            '"bigint unsigned"',
            "VIP_BUILD_COMMIT",
            "g_pFullFileSystem->RenameFile",
            "runtime-probe/v2",
        ):
            self.assertIn(required, self.factory)


if __name__ == "__main__":
    unittest.main()
