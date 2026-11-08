"""
lateralmove.py - Volatility 3 plugin for lateral movement detection.

Detects three categories of indicators:
  Module 1 - Suspicious parent-child process relationships
             (WMI, PsExec, DCOM, scheduled tasks, MMC, browser proxy tools)
  Module 2 - Suspicious network connections
             (SMB, RPC, WinRM, lsass outbound, non-browser HTTP/S)
  Module 3 - Token and session anomalies
             (session ID mismatches from non-bridge parents, privilege escalation)

Usage:
    python vol.py -f memory.dmp windows.lateralmove
    python vol.py -f memory.dmp windows.lateralmove --lateralmove.config-file custom_combos.json

Custom config format (JSON):
    {
        "winword.exe": [["cmd.exe", "powershell.exe"], "Macro execution"],
        "excel.exe":   [["cmd.exe", "powershell.exe"], "Macro execution"]
    }

Install:
    Copy this file to: volatility3/volatility3/plugins/windows/lateralmove.py

API verified against Volatility 2.27.0:
    pslist.PsList._version          = (3, 0, 1)
    netscan.NetScan._version        = (2, 0, 0)
    PsList.list_processes params    = (context, kernel_module_name, filter_func)
    NetScan.scan params             = (context, kernel_module_name, netscan_symbol_table)
    NetScan.create_netscan_symbol_table = (context, kernel_module_name, config_path)

Author: Philip Vieyra (github: cybernerdphil)
"""

import logging
from typing import Dict, Iterator, List, Optional, Set, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import netscan, pslist

vollog = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MITRE ATT&CK technique mappings
# ---------------------------------------------------------------------------
MITRE: Dict[str, str] = {
    "WMI execution":           "T1021.003",
    "PsExec / remote service": "T1021.002",
    "DCOM execution":          "T1021.003",
    "Scheduled task spawn":    "T1053.005",
    "MMC DCOM":                "T1021.003",
    "SMB connection":          "T1021.002",
    "WinRM connection":        "T1021.006",
    "RPC/DCOM port":           "T1021.003",
    "Suspicious lsass conn":   "T1003.001",
    "Non-browser HTTP/S":      "T1071.001",
    "Token impersonation":     "T1134.001",
    "Privilege escalation":    "T1134.002",
    "Proxy/tunnel tool":       "T1090.001",
}

# Processes that legitimately bridge session 0 -> user sessions.
# Session mismatch from these parents is normal Windows behaviour.
SESSION_BRIDGE_PARENTS: Set[str] = {
    "smss.exe", "services.exe", "svchost.exe", "wininit.exe",
    "winlogon.exe", "csrss.exe", "lsass.exe", "taskschd.exe",
}

# Child process names that make a session mismatch suspicious
SESSION_MISMATCH_SUSPICIOUS_CHILDREN: Set[str] = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
}


def _get_session(proc) -> int:
    """Safely get session ID - attribute name varies by Windows version."""
    try:
        return int(proc.Session)
    except AttributeError:
        pass
    try:
        return int(proc.SessionId)
    except AttributeError:
        return -1


class LateralMove(interfaces.plugins.PluginInterface):
    """Detects lateral movement indicators: suspicious parent-child
    relationships, network connections, and token anomalies."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    DEFAULT_COMBOS: Dict[str, Tuple[List[str], str]] = {
        "wmiprvse.exe": (
            ["*"],
            "WMI execution",
        ),
        "services.exe": (
            ["cmd.exe", "powershell.exe", "pwsh.exe",
             "wscript.exe", "cscript.exe", "mshta.exe"],
            "PsExec / remote service",
        ),
        "mmc.exe": (
            ["cmd.exe", "powershell.exe", "pwsh.exe"],
            "MMC DCOM",
        ),
        "dllhost.exe": (
            ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe"],
            "DCOM execution",
        ),
        "taskeng.exe": (
            ["cmd.exe", "powershell.exe", "pwsh.exe",
             "wscript.exe", "cscript.exe"],
            "Scheduled task spawn",
        ),
        "firefox.exe": (
            ["tor.exe", "proxifier.exe", "stunnel.exe"],
            "Proxy/tunnel tool",
        ),
        "chrome.exe": (
            ["tor.exe", "proxifier.exe", "stunnel.exe"],
            "Proxy/tunnel tool",
        ),
        "msedge.exe": (
            ["tor.exe", "proxifier.exe", "stunnel.exe"],
            "Proxy/tunnel tool",
        ),
    }

    SVCHOST_SUSPICIOUS_CHILDREN: List[str] = [
        "cmd.exe", "powershell.exe", "pwsh.exe",
        "wscript.exe", "cscript.exe", "mshta.exe",
    ]

    LATERAL_PORTS: Dict[int, str] = {
        445:  "SMB connection",
        139:  "SMB connection",
        135:  "RPC/DCOM port",
        5985: "WinRM connection",
        5986: "WinRM connection",
    }

    BROWSER_NAMES: Set[str] = {
        "chrome.exe", "firefox.exe", "msedge.exe",
        "iexplore.exe", "opera.exe", "brave.exe",
    }

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist",
                component=pslist.PsList,
                version=(3, 0, 1),
            ),
            requirements.VersionRequirement(
                name="netscan",
                component=netscan.NetScan,
                version=(2, 0, 0),
            ),
            requirements.StringRequirement(
                name="config-file",
                description="Path to JSON file with custom parent-child combos",
                optional=True,
                default=None,
            ),
            requirements.BooleanRequirement(
                name="all-connections",
                description="Include non-ESTABLISHED connections in Module 2",
                optional=True,
                default=False,
            ),
        ]

    def _check_parent_child(
        self,
        proc_name: str,
        parent_name: str,
        combos: Dict,
    ) -> Optional[str]:
        parent_lower = parent_name.lower()
        child_lower = proc_name.lower()

        if parent_lower in combos:
            children, technique = combos[parent_lower]
            if "*" in children or child_lower in [c.lower() for c in children]:
                return technique

        if parent_lower == "svchost.exe":
            if child_lower in [c.lower() for c in self.SVCHOST_SUSPICIOUS_CHILDREN]:
                return "Scheduled task spawn"

        return None

    def _check_connections(
        self,
        pid: int,
        proc_name: str,
        connections: Dict[int, List],
    ) -> List[Tuple[str, str]]:
        findings: List[Tuple[str, str]] = []

        for conn in connections.get(pid, []):
            try:
                foreign_port = int(conn.ForeignPort)

                if proc_name.lower() == "lsass.exe" and foreign_port > 0:
                    findings.append(("Suspicious lsass conn", f"port {foreign_port}"))
                    continue

                if foreign_port in self.LATERAL_PORTS:
                    findings.append((self.LATERAL_PORTS[foreign_port], f"port {foreign_port}"))

                if foreign_port in (80, 443) and proc_name.lower() not in self.BROWSER_NAMES:
                    findings.append(("Non-browser HTTP/S", f"{proc_name} port {foreign_port}"))

            except (exceptions.InvalidAddressException, AttributeError):
                continue

        return findings

    def _check_token(
        self,
        proc,
        proc_name: str,
        parent_name: str,
        parent_session: int,
    ) -> List[str]:
        findings: List[str] = []

        try:
            proc_session = _get_session(proc)

            if (
                proc_session != -1
                and parent_session != -1
                and proc_session != parent_session
                and parent_name.lower() not in SESSION_BRIDGE_PARENTS
                and proc_name.lower() in SESSION_MISMATCH_SUSPICIOUS_CHILDREN
            ):
                findings.append("Token impersonation")

            try:
                token = proc.Token.dereference().cast("_TOKEN")
                groups = token.Groups
                for i in range(int(token.GroupCount)):
                    group = groups[i]
                    attrs = int(group.Attributes)
                    if attrs & 0x20:
                        sid = group.Sid.dereference()
                        sub = int(sid.SubAuthority[0])
                        if sub >= 0x3000 and proc_session > 0:
                            findings.append("Privilege escalation")
                            break
            except (exceptions.InvalidAddressException, AttributeError):
                pass

        except (exceptions.InvalidAddressException, AttributeError):
            pass

        return findings

    def _load_combos(self) -> Dict:
        combos = dict(self.DEFAULT_COMBOS)
        config_path = self.config.get("config-file")

        if config_path:
            try:
                import json

                with open(config_path) as f:
                    user_combos = json.load(f)
                combos.update({k.lower(): v for k, v in user_combos.items()})
                vollog.info(
                    "Loaded %d custom combos from %s", len(user_combos), config_path
                )
            except Exception as exc:
                vollog.warning("Could not load config file %s: %s", config_path, exc)

        return combos

    def _generator(self) -> Iterator[Tuple[int, Tuple]]:
        kernel_name = self.config["kernel"]
        combos = self._load_combos()

        proc_map: Dict[int, Tuple[str, int]] = {}
        all_procs = list(
            pslist.PsList.list_processes(
                context=self.context,
                kernel_module_name=kernel_name,
            )
        )

        for proc in all_procs:
            try:
                name = proc.ImageFileName.cast(
                    "string",
                    max_length=proc.ImageFileName.vol.count,
                    errors="replace",
                )
                proc_map[int(proc.UniqueProcessId)] = (name, _get_session(proc))
            except exceptions.InvalidAddressException:
                continue

        connections: Dict[int, List] = {}
        try:
            netscan_table = netscan.NetScan.create_netscan_symbol_table(
                context=self.context,
                kernel_module_name=kernel_name,
                config_path=self.config_path,
            )
            for conn in netscan.NetScan.scan(
                context=self.context,
                kernel_module_name=kernel_name,
                netscan_symbol_table=netscan_table,
            ):
                try:
                    pid = int(conn.Owner.UniqueProcessId)
                    connections.setdefault(pid, []).append(conn)
                except (exceptions.InvalidAddressException, AttributeError):
                    continue
        except Exception as exc:
            vollog.warning("NetScan unavailable, Module 2 skipped: %s", exc)

        seen: Set[Tuple[int, str]] = set()

        for proc in all_procs:
            try:
                pid = int(proc.UniqueProcessId)
                ppid = int(proc.InheritedFromUniqueProcessId)

                name = proc.ImageFileName.cast(
                    "string",
                    max_length=proc.ImageFileName.vol.count,
                    errors="replace",
                )

                try:
                    peb = proc.Peb.dereference()
                    cmdline = peb.ProcessParameters.CommandLine.get_string() or ""
                except Exception:
                    cmdline = ""

                parent_name, parent_session = proc_map.get(ppid, ("unknown", -1))
                all_findings: List[Tuple[str, str]] = []

                hit = self._check_parent_child(name, parent_name, combos)
                if hit:
                    all_findings.append((hit, MITRE.get(hit, "-")))

                for technique, _detail in self._check_connections(pid, name, connections):
                    all_findings.append((technique, MITRE.get(technique, "-")))

                for technique in self._check_token(proc, name, parent_name, parent_session):
                    all_findings.append((technique, MITRE.get(technique, "-")))

                for technique, mitre_id in all_findings:
                    key = (pid, technique)
                    if key in seen:
                        continue
                    seen.add(key)

                    yield (
                        0,
                        (
                            pid,
                            ppid,
                            name,
                            parent_name,
                            cmdline[:120],
                            technique,
                            mitre_id,
                        ),
                    )

            except exceptions.InvalidAddressException:
                continue

    def run(self):
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("PPID", int),
                ("Process", str),
                ("Parent", str),
                ("CmdLine", str),
                ("Technique", str),
                ("MITRE", str),
            ],
            self._generator(),
        )