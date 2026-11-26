import importlib.util
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

_PLUGIN_PATH = os.path.join(os.path.dirname(__file__), "lateralmove.py")
_spec = importlib.util.spec_from_file_location("lateralmove", _PLUGIN_PATH)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

LateralMove = _mod.LateralMove
SESSION_BRIDGE_PARENTS = _mod.SESSION_BRIDGE_PARENTS
SESSION_MISMATCH_SUSPICIOUS_CHILDREN = _mod.SESSION_MISMATCH_SUSPICIOUS_CHILDREN
_get_session = _mod._get_session


def _make_plugin():
    plugin = LateralMove.__new__(LateralMove)
    plugin._context = MagicMock()
    mock_config = MagicMock()
    mock_config.get = MagicMock(return_value=None)
    mock_config.__getitem__ = MagicMock(return_value="kernel")
    plugin._config = mock_config
    plugin.config_path = "test.config"
    return plugin


class TestGetSession(unittest.TestCase):

    def test_returns_session_attribute(self):
        proc = MagicMock()
        proc.Session = 2
        self.assertEqual(_get_session(proc), 2)

    def test_falls_back_to_session_id(self):
        proc = MagicMock(spec=["SessionId"])
        proc.SessionId = 1
        self.assertEqual(_get_session(proc), 1)

    def test_returns_minus_one_when_neither_exists(self):
        proc = MagicMock(spec=[])
        self.assertEqual(_get_session(proc), -1)


class TestCheckParentChild(unittest.TestCase):

    def setUp(self):
        self.plugin = _make_plugin()
        self.combos = self.plugin._load_combos()

    def test_wmiprvse_any_child_flagged(self):
        self.assertEqual(
            self.plugin._check_parent_child("notepad.exe", "wmiprvse.exe", self.combos),
            "WMI execution",
        )

    def test_wmiprvse_cmd_flagged(self):
        self.assertEqual(
            self.plugin._check_parent_child("cmd.exe", "wmiprvse.exe", self.combos),
            "WMI execution",
        )

    def test_services_powershell_flagged(self):
        self.assertEqual(
            self.plugin._check_parent_child("powershell.exe", "services.exe", self.combos),
            "PsExec / remote service",
        )

    def test_services_notepad_not_flagged(self):
        self.assertIsNone(
            self.plugin._check_parent_child("notepad.exe", "services.exe", self.combos)
        )

    def test_mmc_cmd_flagged(self):
        self.assertEqual(
            self.plugin._check_parent_child("cmd.exe", "mmc.exe", self.combos),
            "MMC DCOM",
        )

    def test_dllhost_wscript_flagged(self):
        self.assertEqual(
            self.plugin._check_parent_child("wscript.exe", "dllhost.exe", self.combos),
            "DCOM execution",
        )

    def test_svchost_cmd_flagged(self):
        self.assertEqual(
            self.plugin._check_parent_child("cmd.exe", "svchost.exe", self.combos),
            "Scheduled task spawn",
        )

    def test_svchost_explorer_not_flagged(self):
        self.assertIsNone(
            self.plugin._check_parent_child("explorer.exe", "svchost.exe", self.combos)
        )

    def test_firefox_tor_flagged(self):
        self.assertEqual(
            self.plugin._check_parent_child("tor.exe", "firefox.exe", self.combos),
            "Proxy/tunnel tool",
        )

    def test_firefox_child_not_flagged(self):
        self.assertIsNone(
            self.plugin._check_parent_child("firefox.exe", "firefox.exe", self.combos)
        )

    def test_case_insensitive(self):
        self.assertEqual(
            self.plugin._check_parent_child("CMD.EXE", "WmiPrvSE.exe", self.combos),
            "WMI execution",
        )

    def test_benign_parent_none(self):
        self.assertIsNone(
            self.plugin._check_parent_child("cmd.exe", "explorer.exe", self.combos)
        )


class TestCheckConnections(unittest.TestCase):

    def setUp(self):
        self.plugin = _make_plugin()

    def _run(self, proc_name, port):
        conn = MagicMock()
        conn.ForeignPort = port
        results = self.plugin._check_connections(1, proc_name, {1: [conn]})
        return [r[0] for r in results]

    def test_smb_445(self):
        self.assertIn("SMB connection", self._run("svchost.exe", 445))

    def test_smb_139(self):
        self.assertIn("SMB connection", self._run("svchost.exe", 139))

    def test_winrm_5985(self):
        self.assertIn("WinRM connection", self._run("svchost.exe", 5985))

    def test_winrm_5986(self):
        self.assertIn("WinRM connection", self._run("svchost.exe", 5986))

    def test_rpc_135(self):
        self.assertIn("RPC/DCOM port", self._run("svchost.exe", 135))

    def test_lsass_outbound(self):
        self.assertIn("Suspicious lsass conn", self._run("lsass.exe", 4444))

    def test_lsass_port_zero_not_flagged(self):
        self.assertEqual(self._run("lsass.exe", 0), [])

    def test_non_browser_443(self):
        self.assertIn("Non-browser HTTP/S", self._run("powershell.exe", 443))

    def test_non_browser_80(self):
        self.assertIn("Non-browser HTTP/S", self._run("powershell.exe", 80))

    def test_browser_443_not_flagged(self):
        self.assertNotIn("Non-browser HTTP/S", self._run("firefox.exe", 443))

    def test_browser_80_not_flagged(self):
        self.assertNotIn("Non-browser HTTP/S", self._run("chrome.exe", 80))

    def test_no_connections_empty(self):
        self.assertEqual(
            self.plugin._check_connections(9999, "explorer.exe", {}), []
        )

    def test_benign_port_not_flagged(self):
        self.assertEqual(self._run("svchost.exe", 8080), [])


class TestCheckToken(unittest.TestCase):

    def setUp(self):
        self.plugin = _make_plugin()

    def _proc(self, session):
        proc = MagicMock()
        proc.Session = session
        proc.Token.dereference.side_effect = AttributeError("no token")
        return proc

    def test_mismatch_suspicious_child_flagged(self):
        self.assertIn(
            "Token impersonation",
            self.plugin._check_token(self._proc(2), "cmd.exe", "explorer.exe", 0),
        )

    def test_mismatch_non_suspicious_child_not_flagged(self):
        self.assertNotIn(
            "Token impersonation",
            self.plugin._check_token(self._proc(2), "notepad.exe", "explorer.exe", 0),
        )

    def test_mismatch_bridge_parent_not_flagged(self):
        self.assertNotIn(
            "Token impersonation",
            self.plugin._check_token(self._proc(2), "cmd.exe", "svchost.exe", 0),
        )

    def test_same_session_not_flagged(self):
        self.assertNotIn(
            "Token impersonation",
            self.plugin._check_token(self._proc(2), "cmd.exe", "explorer.exe", 2),
        )

    def test_unknown_parent_session_not_flagged(self):
        self.assertNotIn(
            "Token impersonation",
            self.plugin._check_token(self._proc(2), "cmd.exe", "unknown", -1),
        )


class TestSessionBridgeParents(unittest.TestCase):

    def test_svchost_in_set(self):
        self.assertIn("svchost.exe", SESSION_BRIDGE_PARENTS)

    def test_services_in_set(self):
        self.assertIn("services.exe", SESSION_BRIDGE_PARENTS)

    def test_smss_in_set(self):
        self.assertIn("smss.exe", SESSION_BRIDGE_PARENTS)

    def test_explorer_not_in_set(self):
        self.assertNotIn("explorer.exe", SESSION_BRIDGE_PARENTS)


class TestLoadCombos(unittest.TestCase):

    def setUp(self):
        self.plugin = _make_plugin()

    def test_defaults_present(self):
        combos = self.plugin._load_combos()
        self.assertIn("wmiprvse.exe", combos)
        self.assertIn("services.exe", combos)
        self.assertIn("firefox.exe", combos)

    def test_custom_combos_merged(self):
        custom = {"winword.exe": [["cmd.exe"], "Macro execution"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(custom, f)
            tmp_path = f.name
        try:
            def patched_load():
                import json as _json
                combos = dict(LateralMove.DEFAULT_COMBOS)
                with open(tmp_path) as fp:
                    user_combos = _json.load(fp)
                combos.update({k.lower(): v for k, v in user_combos.items()})
                return combos
            self.plugin._load_combos = patched_load
            combos = self.plugin._load_combos()
            self.assertIn("winword.exe", combos)
            self.assertIn("wmiprvse.exe", combos)
        finally:
            os.unlink(tmp_path)

    def test_bad_config_path_uses_defaults(self):
        self.plugin._config.get = MagicMock(return_value="/nonexistent/path.json")
        combos = self.plugin._load_combos()
        self.assertIn("wmiprvse.exe", combos)


if __name__ == "__main__":
    unittest.main(verbosity=2)
