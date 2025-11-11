import logging
from typing import List, Dict, Any, Set, Tuple, Optional
from volatility3.framework import interfaces, renderers, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, psscan, handles, dlllist
from volatility3.framework.objects import utility
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import extensions

vollog = logging.getLogger(__name__)

class PSParent(interfaces.plugins.PluginInterface):
    """
    Dynamic Parent-Child Process Relationship Validation
    Uses built-in Windows behaviors to detect anomalies
    """

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel module",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.BooleanRequirement(
                name="verbose",
                description="Show additional process details",
                optional=True,
                default=False
            ),
            requirements.BooleanRequirement(
                name="debug",
                description="Show debug information",
                optional=True,
                default=False
            ),
            requirements.IntRequirement(
                name="pid",
                description="Filter by specific Process ID",
                optional=True,
                default=None
            ),
            requirements.BooleanRequirement(
                name="show-legitimate",
                description="Show legitimate processes for comparison",
                optional=True,
                default=True
            )
        ]
    
    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        verbose = self.config.get("verbose", False)
        debug = self.config.get("debug", False)
        target_pid = self.config.get("pid")
        show_legitimate = self.config.get("show-legitimate", True)
        
        vollog.info("Starting dynamic parent-child process analysis...")
        
        # Build comprehensive process map using built-in data
        processes = self._build_process_map(debug)
        
        if debug:
            vollog.info(f"Analyzing {len(processes)} processes")
        
        # Analyze each process using dynamic Windows behavior rules
        for pid, proc_info in processes.items():
            try:
                if target_pid is not None and pid != target_pid:
                    continue
                
                # Get analysis results
                analysis = self._analyze_process_dynamically(pid, proc_info, processes, debug)
                
                # Show legitimate processes if requested
                if show_legitimate or analysis['status'] != 'LEGITIMATE':
                    yield self._format_output(proc_info, analysis, verbose)
                    
            except Exception as e:
                if debug:
                    vollog.error(f"Error analyzing PID {pid}: {e}")
                continue
    
    def _build_process_map(self, debug: bool) -> Dict[int, Dict[str, Any]]:
        """Build process map using built-in Windows data structures"""
        processes = {}
        
        for proc in pslist.PsList.list_processes(self.context, self.config["kernel"]):
            try:
                pid = int(proc.UniqueProcessId)
                ppid = int(proc.InheritedFromUniqueProcessId)
                name = self._get_process_name(proc)
                
                processes[pid] = {
                    'process': proc,
                    'name': name,
                    'ppid': ppid,
                    'create_time': self._get_create_time(proc),
                    'session_id': self._get_session_id(proc),
                    'integrity': self._get_integrity_level(proc),
                    'is_protected': self._is_protected_process(proc),
                    'parent_name': self._get_parent_name(processes, ppid) if ppid in processes else "Unknown"
                }
                
            except Exception as e:
                if debug:
                    vollog.debug(f"Error building process map for PID {pid}: {e}")
                continue
        
        return processes
    
    def _analyze_process_dynamically(self, pid: int, proc_info: Dict, processes: Dict, debug: bool) -> Dict[str, Any]:
        """Dynamically analyze process using Windows behavior rules"""
        name = proc_info['name']
        ppid = proc_info['ppid']
        
        # Initialize analysis result
        analysis = {
            'status': 'LEGITIMATE',
            'severity': 'INFO',
            'evidence': 'Normal parent-child relationship',
            'technique': 'Normal Execution',
            'confidence': 'HIGH'
        }
        
        # Rule 1: Check if parent process exists
        if not self._is_valid_parent(ppid, processes):
            analysis.update({
                'status': 'SUSPICIOUS',
                'severity': 'HIGH',
                'evidence': f'Parent process (PID {ppid}) does not exist',
                'technique': 'Process Orphaning',
                'confidence': 'HIGH'
            })
            return analysis
        
        parent_info = processes[ppid]
        
        # Rule 2: Check session consistency
        if not self._is_session_consistent(proc_info, parent_info):
            analysis.update({
                'status': 'SUSPICIOUS',
                'severity': 'MEDIUM',
                'evidence': f'Session mismatch: Child in {proc_info["session_id"]}, Parent in {parent_info["session_id"]}',
                'technique': 'Cross-Session Injection',
                'confidence': 'MEDIUM'
            })
            return analysis
        
        # Rule 3: Check integrity level inheritance (ONLY if both are available)
        integrity_violation = self._check_integrity_violation(proc_info, parent_info)
        if integrity_violation:
            analysis.update(integrity_violation)
            return analysis
        
        # Rule 4: Check creation time consistency
        if not self._is_time_consistent(proc_info, parent_info):
            analysis.update({
                'status': 'SUSPICIOUS',
                'severity': 'HIGH', 
                'evidence': 'Child process created before parent',
                'technique': 'Process Tampering',
                'confidence': 'HIGH'
            })
            return analysis
        
        # Rule 5: Check protected process violations (ONLY if detection is reliable)
        protection_violation = self._check_protection_violation(proc_info, parent_info)
        if protection_violation:
            analysis.update(protection_violation)
            return analysis
        
        # Rule 6: Check for system process anomalies
        system_anomaly = self._check_system_process_anomaly(proc_info, parent_info)
        if system_anomaly:
            analysis.update(system_anomaly)
            return analysis
        
        return analysis
    
    def _is_valid_parent(self, ppid: int, processes: Dict) -> bool:
        """Check if parent process exists and is valid"""
        # PID 0 and 4 are valid system parents
        if ppid in [0, 4]:
            return True
        
        # Check if parent exists in process list
        return ppid in processes
    
    def _is_session_consistent(self, child_info: Dict, parent_info: Dict) -> bool:
        """Check if session IDs are consistent"""
        child_session = child_info.get('session_id', -1)
        parent_session = parent_info.get('session_id', -1)
        
        # Skip if session info unavailable
        if child_session == -1 or parent_session == -1:
            return True
        
        child_name = child_info['name'].lower()
        parent_name = parent_info['name'].lower()
        
        # Services can create processes in different sessions
        if parent_name in ['services.exe', 'svchost.exe', 'wininit.exe']:
            return True
        
        # Winlogon can create processes in user sessions
        if parent_name in ['winlogon.exe', 'userinit.exe']:
            return True
        
        # smss.exe creates session-specific processes
        if parent_name == 'smss.exe':
            return True
        
        # Per-session system processes
        if child_name in ['dwm.exe', 'csrss.exe', 'winlogon.exe', 'logonui.exe']:
            return True
        
        # Task Scheduler can launch processes in different sessions
        if parent_name in ['taskeng.exe', 'taskhostw.exe', 'taskhostt.exe']:
            return True
        
        # COM surrogate and DLL host processes
        if parent_name in ['dllhost.exe', 'rundll32.exe']:
            return True
        
        # Normally, child should be in same session as parent
        return child_session == parent_session
    
    def _check_integrity_violation(self, child_info: Dict, parent_info: Dict) -> Optional[Dict[str, Any]]:
        """Check integrity level consistency - only flag if we have reliable data"""
        child_integrity = child_info.get('integrity', 'Unknown')
        parent_integrity = parent_info.get('integrity', 'Unknown')
        
        # Skip entirely if integrity info unavailable or unreliable
        if child_integrity == 'Unknown' or parent_integrity == 'Unknown':
            return None
        
        # Define integrity hierarchy
        integrity_levels = {'Low': 0, 'Medium': 1, 'High': 2, 'System': 3}
        child_level = integrity_levels.get(child_integrity, -1)
        parent_level = integrity_levels.get(parent_integrity, -1)
        
        # Skip if we couldn't parse levels
        if child_level == -1 or parent_level == -1:
            return None
        
        # Allow same level or lower (child inheriting or being lowered)
        if child_level <= parent_level:
            return None
        
        # Child has higher integrity than parent - suspicious
        return {
            'status': 'SUSPICIOUS', 
            'severity': 'HIGH',
            'evidence': f'Integrity violation: Child({child_integrity}) > Parent({parent_integrity})',
            'technique': 'Token Manipulation',
            'confidence': 'HIGH'
        }
    
    def _is_time_consistent(self, child_info: Dict, parent_info: Dict) -> bool:
        """Check process creation time consistency"""
        child_time = child_info.get('create_time')
        parent_time = parent_info.get('create_time')
        
        # Skip if time info unavailable
        if not child_time or not parent_time:
            return True
        
        # Child should never be created before parent
        return child_time >= parent_time
    
    def _check_protection_violation(self, child_info: Dict, parent_info: Dict) -> Optional[Dict[str, Any]]:
        """Check protected process consistency - only flag if detection is reliable"""
        child_protected = child_info.get('is_protected', False)
        parent_protected = parent_info.get('is_protected', False)
        
        # Only flag if we're certain the child is protected and parent is not
        # Since our detection may be unreliable, be conservative
        if child_protected and not parent_protected:
            # Additional validation: check if this is a known legitimate scenario
            child_name = child_info['name'].lower()
            parent_name = parent_info['name'].lower()
            
            # Some protected processes legitimately spawned by unprotected parents
            # (e.g., services.exe spawning protected services)
            if parent_name in ['services.exe', 'wininit.exe', 'smss.exe']:
                return None
            
            return {
                'status': 'SUSPICIOUS',
                'severity': 'CRITICAL',
                'evidence': f'Protected process {child_name} spawned by unprotected {parent_name}',
                'technique': 'Protected Process Bypass',
                'confidence': 'MEDIUM'  # Lower confidence due to detection reliability
            }
        
        return None
    
    def _check_system_process_anomaly(self, child_info: Dict, parent_info: Dict) -> Optional[Dict[str, Any]]:
        """Check for system process anomalies using dynamic rules"""
        child_name = child_info['name'].lower()
        parent_name = parent_info['name'].lower()
        
        # Critical system processes with strict parent requirements
        critical_system_processes = {
            'csrss.exe': {'smss.exe'},
            'wininit.exe': {'smss.exe'},
            'smss.exe': {'system', 'ntoskrnl.exe'},
        }
        
        # Important system processes with known valid parents
        # Comprehensive list of Windows system processes and their legitimate parents
        system_processes = {
            # Core Windows processes
            'lsass.exe': {'wininit.exe'},
            'services.exe': {'wininit.exe'},
            'winlogon.exe': {'smss.exe'},
            
            # Session Manager and related
            'lsm.exe': {'wininit.exe'},  # Local Session Manager
            'lsaiso.exe': {'wininit.exe'},  # LSA Isolated
            
            # User session processes
            'userinit.exe': {'winlogon.exe'},
            'dwm.exe': {'svchost.exe', 'winlogon.exe'},  # Desktop Window Manager
            'logonui.exe': {'winlogon.exe'},
            'consent.exe': {'svchost.exe'},  # UAC consent UI
            
            # Explorer and shell
            'explorer.exe': {'userinit.exe', 'explorer.exe'},  # Can spawn itself
            'sihost.exe': {'svchost.exe'},  # Shell Infrastructure Host
            'shellexperiencehost.exe': {'svchost.exe'},
            'startmenuexperiencehost.exe': {'svchost.exe'},
            'searchindexer.exe': {'services.exe'},
            'searchprotocolhost.exe': {'searchindexer.exe'},
            'searchfilterhost.exe': {'searchindexer.exe'},
            
            # Service hosts and related
            'svchost.exe': {'services.exe'},
            'taskhost.exe': {'svchost.exe'},
            'taskhostw.exe': {'svchost.exe'},
            'taskhostt.exe': {'svchost.exe'},
            
            # Task Scheduler
            'taskeng.exe': {'services.exe'},  # Task Scheduler Engine (older)
            'schedule.exe': {'services.exe'},
            
            # Windows Update and maintenance
            'wuauclt.exe': {'svchost.exe'},
            'trustedinstaller.exe': {'services.exe'},
            'tiworker.exe': {'svchost.exe'},
            'musnotification.exe': {'svchost.exe'},
            
            # Security and protection
            'msmpeng.exe': {'services.exe', 'svchost.exe'},  # Windows Defender
            'mssense.exe': {'services.exe', 'svchost.exe'},  # Defender ATP
            'securityhealthservice.exe': {'services.exe', 'svchost.exe'},
            'smartscreen.exe': {'svchost.exe'},
            
            # Audio and multimedia
            'audiodg.exe': {'svchost.exe'},  # Windows Audio Device Graph
            
            # Network and connectivity
            'dashost.exe': {'svchost.exe'},  # Device Association Framework
            'ngen.exe': {'mscorsvw.exe', 'services.exe'},
            'mscorsvw.exe': {'services.exe'},
            
            # Runtime and hosting
            'runtimebroker.exe': {'svchost.exe'},
            'dllhost.exe': {'svchost.exe', 'explorer.exe'},
            'com.surrogate': {'svchost.exe', 'dllhost.exe'},
            
            # System utilities
            'spoolsv.exe': {'services.exe'},  # Print Spooler
            'sppsvc.exe': {'services.exe'},  # Software Protection Platform
            'ctfmon.exe': {'explorer.exe', 'svchost.exe'},  # Text Input
            
            # Windows Management
            'wmiprvse.exe': {'svchost.exe'},  # WMI Provider Host
            'wmiapsrv.exe': {'svchost.exe'},
            'unsecapp.exe': {'svchost.exe'},
            
            # Registry
            'conhost.exe': {'csrss.exe', 'explorer.exe', 'cmd.exe', 'powershell.exe', 'services.exe'},
            
            # Fonts and display
            'fontdrvhost.exe': {'dwm.exe', 'csrss.exe'},
            
            # Application Frame Host
            'applicationframehost.exe': {'svchost.exe'},
            
            # System Settings and Configuration
            'systemsettings.exe': {'explorer.exe', 'sihost.exe'},
            'systemsettingsbroker.exe': {'svchost.exe'},
            
            # User Account Control
            'consent.exe': {'svchost.exe'},
            
            # Windows Store and Apps
            'wsappx': {'svchost.exe'},
            
            # Background Task Host
            'backgroundtaskhost.exe': {'svchost.exe'},
            
            # Compatibility Telemetry
            'compattelrunner.exe': {'svchost.exe'},
            
            # Windows Error Reporting
            'werfault.exe': {'svchost.exe', 'services.exe'},
            'wermgr.exe': {'svchost.exe'},
            
            # Memory Compression
            'system': {''},  # Special case for System process
            
            # Modern Apps and UWP
            'mobsync.exe': {'svchost.exe'},
            
            # TPM and Security
            'tpautomatsvc.exe': {'services.exe'},
            
            # BitLocker
            'fvenotify.exe': {'explorer.exe'},
            
            # Windows Time Service
            'vssvc.exe': {'services.exe'},  # Volume Shadow Copy
            
            # BITS (Background Intelligent Transfer)
            'bitsadmin.exe': {'svchost.exe'},
            
            # Certificate Services
            'csrss.exe': {'smss.exe'},
            
            # Delivery Optimization
            'dosvc.exe': {'services.exe'},
            
            # Microsoft Edge WebView
            'msedgewebview2.exe': {'explorer.exe', 'svchost.exe'},
            
            # Phone Link / Your Phone
            'yourphone.exe': {'explorer.exe', 'sihost.exe'},
            
            # Windows Installer
            'msiexec.exe': {'services.exe', 'explorer.exe'},
            
            # Group Policy
            'gpscript.exe': {'svchost.exe'},
            
            # Windows Licensing
            'licensingui.exe': {'explorer.exe'},
            
            # Cloud Experience Host
            'cloudexperiencehostbroker.exe': {'svchost.exe'},
        }
        
        # Check critical processes first (high confidence)
        for sys_proc, valid_parents in critical_system_processes.items():
            if child_name == sys_proc:
                valid_parents_lower = {p.lower() for p in valid_parents}
                if parent_name not in valid_parents_lower:
                    return {
                        'status': 'MALICIOUS',
                        'severity': 'CRITICAL',
                        'evidence': f'Critical system process {child_info["name"]} has invalid parent {parent_info["name"]}',
                        'technique': 'PPID Spoofing / Process Hollowing',
                        'confidence': 'HIGH'
                    }
        
        # Check standard system processes (medium confidence)
        for sys_proc, valid_parents in system_processes.items():
            if child_name == sys_proc:
                valid_parents_lower = {p.lower() for p in valid_parents}
                # Skip empty parent set (like for 'system')
                if not valid_parents_lower or '' in valid_parents_lower:
                    continue
                if parent_name not in valid_parents_lower:
                    # Lower severity for less critical processes
                    return {
                        'status': 'SUSPICIOUS',
                        'severity': 'HIGH',
                        'evidence': f'System process {child_info["name"]} has unexpected parent {parent_info["name"]}',
                        'technique': 'Possible PPID Spoofing',
                        'confidence': 'MEDIUM'
                    }
        
        return None
    
    def _get_process_name(self, proc) -> str:
        """Safely extract process name"""
        try:
            return utility.array_to_string(proc.ImageFileName)
        except:
            try:
                return proc.ImageFileName.cast(
                    "string",
                    max_length=proc.ImageFileName.vol.count,
                    errors="replace"
                )
            except:
                return "Unknown"
    
    def _get_create_time(self, proc) -> Optional[float]:
        """Get process creation time"""
        try:
            if hasattr(proc, 'CreateTime'):
                return float(proc.CreateTime)
        except:
            pass
        return None
    
    def _get_session_id(self, proc) -> int:
        """Get process session ID"""
        try:
            if hasattr(proc, 'SessionId'):
                return int(proc.SessionId)
        except:
            pass
        return -1
    
    def _get_integrity_level(self, proc) -> str:
        """Get process integrity level - returns Unknown if unreliable"""
        try:
            # Attempt to get integrity level from token
            # This is a simplified version - real implementation needs token parsing
            if hasattr(proc, 'Token') and proc.Token:
                # Without proper token parsing, we cannot reliably determine integrity
                # Return Unknown to avoid false positives
                return "Unknown"
        except:
            pass
        return "Unknown"
    
    def _is_protected_process(self, proc) -> bool:
        """Check if process is protected - conservative detection"""
        try:
            # Check for protected process flags
            if hasattr(proc, 'Protection'):
                # Parse PS_PROTECTION structure if available
                protection = proc.Protection
                if hasattr(protection, 'Level') and int(protection.Level) > 0:
                    return True
            
            # Alternative: Check Flags field (correct field name)
            if hasattr(proc, 'Flags'):
                flags = int(proc.Flags)
                # Check PS_PROCESS_FLAGS for protected process bit
                # This is simplified - actual flag values depend on Windows version
                return flags & 0x00000800 != 0  # PS_PROTECTED_PROCESS flag
        except:
            pass
        return False
    
    def _get_parent_name(self, processes: Dict, ppid: int) -> str:
        """Get parent process name"""
        if ppid in processes:
            return processes[ppid]['name']
        elif ppid == 0:
            return "System"
        elif ppid == 4:
            return "System"
        else:
            return "Unknown"
    
    def _format_output(self, proc_info: Dict, analysis: Dict, verbose: bool) -> Tuple:
        """Format analysis result for output"""
        
        if verbose:
            return (0, (
                proc_info['name'],
                proc_info['process'].UniqueProcessId,
                proc_info['ppid'],
                proc_info['parent_name'],
                analysis['status'],
                analysis['severity'],
                analysis['technique'],
                analysis['evidence'],
                analysis['confidence'],
                proc_info.get('session_id', 'N/A')
            ))
        else:
            return (0, (
                proc_info['name'],
                proc_info['process'].UniqueProcessId,
                proc_info['ppid'],
                proc_info['parent_name'],
                analysis['status'],
                analysis['severity'],
                analysis['evidence']
            ))
    
    def run(self):
        verbose = self.config.get("verbose", False)
        
        if verbose:
            columns = [
                ("Process", str),
                ("PID", int),
                ("PPID", int),
                ("Parent Name", str),
                ("Status", str),
                ("Severity", str),
                ("Technique", str),
                ("Evidence", str),
                ("Confidence", str),
                ("Session", str)
            ]
        else:
            columns = [
                ("Process", str),
                ("PID", int),
                ("PPID", int),
                ("Parent Name", str),
                ("Status", str),
                ("Severity", str),
                ("Evidence", str)
            ]
        
        return renderers.TreeGrid(columns, self._generator())
