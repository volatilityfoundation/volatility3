import logging
from typing import List, Dict, Tuple
from collections import defaultdict
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist, dlllist, registry

vollog = logging.getLogger(__name__)

class SandboxDetect(interfaces.plugins.PluginInterface):
    """Detects sandbox artifacts in Windows memory dumps."""
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)
    
    # Sandbox indicators
    SANDBOX_PROCESSES = {
        'vmtoolsd.exe': 'VMware Tools',
        'vmwaretray.exe': 'VMware Tray',
        'vmwareuser.exe': 'VMware User Process',
        'vboxservice.exe': 'VirtualBox Service',
        'vboxtray.exe': 'VirtualBox Tray',
        'vmsrvc.exe': 'VirtualPC Service',
        'vmusrvc.exe': 'VirtualPC User Service',
        'prl_cc.exe': 'Parallels Coherence',
        'prl_tools.exe': 'Parallels Tools',
        'xenservice.exe': 'Xen Service',
        'qemu-ga.exe': 'QEMU Guest Agent',
        'wireshark.exe': 'Network Analysis Tool',
        'procmon.exe': 'Process Monitor',
        'procexp.exe': 'Process Explorer',
        'ollydbg.exe': 'Debugger',
        'x64dbg.exe': 'Debugger',
        'idaq.exe': 'IDA Pro Debugger',
        'idaq64.exe': 'IDA Pro Debugger',
        'windbg.exe': 'Windows Debugger',
        'sandboxie.exe': 'Sandboxie',
        'cuckoo.exe': 'Cuckoo Sandbox',
        'agent.pyw': 'Cuckoo Agent',
        'fiddler.exe': 'HTTP Proxy/Debugger',
        'regmon.exe': 'Registry Monitor',
        'filemon.exe': 'File Monitor',
    }
    
    SANDBOX_DLLS = [
        'sbiedll.dll',  # Sandboxie
        'dbghelp.dll',  # Debugging
        'api_log.dll',  # API hooking
        'vmGuestLib.dll',  # VMware
        'vboxmrxnp.dll',  # VirtualBox
        'VBoxHook.dll',  # VirtualBox
        'prltools.dll',  # Parallels
    ]
    
    VM_ARTIFACTS = [
        'vmware',
        'vbox',
        'virtualbox',
        'qemu',
        'xen',
        'parallels',
        'virtual',
        'bochs',
        'hyperv',
        'kvm',
    ]
    
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
                description="Show detailed findings",
                optional=True,
                default=False
            ),
        ]
    
    def _check_processes(self, kernel_module_name: str) -> Tuple[int, List[Dict]]:
        """Check for sandbox-related processes."""
        detections = []
        score = 0
        
        for proc in pslist.PsList.list_processes(self.context, kernel_module_name):
            try:
                proc_name = proc.ImageFileName.cast(
                    "string",
                    max_length=proc.ImageFileName.vol.count,
                    errors="replace"
                ).lower()
                
                proc_pid = proc.UniqueProcessId
                
                # Get process path
                try:
                    peb = proc.get_peb()
                    if peb:
                        process_params = peb.ProcessParameters
                        if process_params:
                            image_path = process_params.ImagePathName.get_string()
                            proc_path = image_path if image_path else "N/A"
                        else:
                            proc_path = "N/A"
                    else:
                        proc_path = "N/A"
                except Exception:
                    proc_path = "N/A"
                
                if proc_name in self.SANDBOX_PROCESSES:
                    score += 10
                    detections.append({
                        'type': 'Process',
                        'indicator': proc_name,
                        'description': self.SANDBOX_PROCESSES[proc_name],
                        'severity': 'High',
                        'info': f'PID: {proc_pid} | Path: {proc_path}'
                    })
                
                # Check for VM-related keywords in process names
                for artifact in self.VM_ARTIFACTS:
                    if artifact in proc_name and proc_name not in self.SANDBOX_PROCESSES:
                        score += 5
                        detections.append({
                            'type': 'Process',
                            'indicator': proc_name,
                            'description': f'VM-related keyword: {artifact}',
                            'severity': 'Medium',
                            'info': f'PID: {proc_pid} | Path: {proc_path}'
                        })
                        break
                
            except Exception as e:
                vollog.debug(f"Error checking process: {e}")
                continue
        
        return score, detections
    
    def _check_dlls(self, kernel_module_name: str) -> Tuple[int, List[Dict]]:
        """Check for sandbox-related DLLs."""
        detections = []
        score = 0
        checked_dlls = set()
        
        for proc in pslist.PsList.list_processes(self.context, kernel_module_name):
            try:
                proc_name = proc.ImageFileName.cast(
                    "string",
                    max_length=proc.ImageFileName.vol.count,
                    errors="replace"
                )
                
                for entry in proc.load_order_modules():
                    try:
                        dll_name = entry.BaseDllName.get_string().lower()
                        
                        if dll_name in checked_dlls:
                            continue
                        
                        checked_dlls.add(dll_name)
                        
                        if dll_name in self.SANDBOX_DLLS:
                            score += 8
                            detections.append({
                                'type': 'DLL',
                                'indicator': dll_name,
                                'description': 'Sandbox/Analysis DLL',
                                'severity': 'High',
                                'process': proc_name
                            })
                        
                        # Check for VM-related DLL names
                        for artifact in self.VM_ARTIFACTS:
                            if artifact in dll_name and dll_name not in self.SANDBOX_DLLS:
                                score += 3
                                detections.append({
                                    'type': 'DLL',
                                    'indicator': dll_name,
                                    'description': f'VM-related DLL: {artifact}',
                                    'severity': 'Low',
                                    'process': proc_name
                                })
                                break
                        
                    except Exception:
                        continuenue
                        
            except Exception as e:
                vollog.debug(f"Error checking DLLs: {e}")
                continue
        
        return score, detections
    
    def _check_system_info(self, kernel_module_name: str) -> Tuple[int, List[Dict]]:
        """Check system information for sandbox indicators."""
        detections = []
        score = 0
        
        # Count total processes - sandboxes often have fewer processes
        process_count = 0
        process_names = []
        for proc in pslist.PsList.list_processes(self.context, kernel_module_name):
            process_count += 1
            try:
                proc_name = proc.ImageFileName.cast(
                    "string",
                    max_length=proc.ImageFileName.vol.count,
                    errors="replace"
                ).lower()
                process_names.append(proc_name)
            except Exception:
                continue
        
        # Check for very low process count
        if process_count < 20:
            score += 10
            detections.append({
                'type': 'System',
                'indicator': f'Very low process count: {process_count}',
                'description': 'Critical: Typical systems run 40+ processes',
                'severity': 'High',
                'info': 'Minimal process environment detected'
            })
        elif process_count < 30:
            score += 5
            detections.append({
                'type': 'System',
                'indicator': f'Low process count: {process_count}',
                'description': 'Sandboxes typically run fewer processes',
                'severity': 'Medium',
                'info': 'Limited process environment'
            })
        
        # Check for missing common Windows processes
        common_processes = ['explorer.exe', 'svchost.exe', 'lsass.exe', 'services.exe', 'winlogon.exe']
        missing_processes = [p for p in common_processes if p not in process_names]
        
        if len(missing_processes) >= 2:
            score += 8
            detections.append({
                'type': 'System',
                'indicator': f'Missing critical processes: {", ".join(missing_processes)}',
                'description': 'Essential Windows processes not running',
                'severity': 'High',
                'info': f'Found processes: {", ".join(process_names[:10])}...'
            })
        
        # Check for suspicious timing (all processes started around same time)
        # This would require creation time analysis
        
        return score, detections
    
    def _check_drivers(self, kernel_module_name: str) -> Tuple[int, List[Dict]]:
        """Check for VM/sandbox drivers in loaded modules."""
        detections = []
        score = 0
        
        vm_drivers = [
            'vmmouse.sys', 'vmhgfs.sys', 'vmci.sys', 'vboxguest.sys',
            'vboxsf.sys', 'vboxvideo.sys', 'prl_fs.sys', 'prl_tg.sys'
        ]
        
        # This would require kernel module enumeration
        # Simplified version checking process loaded modules
        checked_modules = set()
        
        for proc in pslist.PsList.list_processes(self.context, kernel_module_name):
            try:
                proc_name = proc.ImageFileName.cast(
                    "string",
                    max_length=proc.ImageFileName.vol.count,
                    errors="replace"
                )
                proc_pid = proc.UniqueProcessId
                
                for entry in proc.load_order_modules():
                    try:
                        dll_name = entry.BaseDllName.get_string().lower()
                        dll_path = entry.FullDllName.get_string()
                        
                        if dll_name in checked_modules:
                            continue
                        
                        checked_modules.add(dll_name)
                        
                        if dll_name in vm_drivers:
                            score += 15
                            detections.append({
                                'type': 'Driver',
                                'indicator': dll_name,
                                'description': 'VM/Sandbox driver detected',
                                'severity': 'Critical',
                                'info': f'Process: {proc_name} (PID: {proc_pid}) | Path: {dll_path}'
                            })
                    except Exception:
                        continue
            except Exception:
                continue
        
        return score, detections
    
    def _calculate_verdict(self, total_score: int, detection_count: int) -> Tuple[str, str]:
        """Calculate final verdict based on score and detections."""
        if total_score >= 50 or detection_count >= 5:
            return "SANDBOX", "High confidence - Multiple sandbox indicators detected"
        elif total_score >= 30 or detection_count >= 3:
            return "LIKELY SANDBOX", "Medium confidence - Several suspicious indicators"
        elif total_score >= 15 or detection_count >= 1:
            return "SUSPICIOUS", "Low confidence - Few indicators detected"
        else:
            return "REAL MACHINE", "No significant sandbox indicators found"
    
    def _generator(self):
        kernel_module_name = self.config["kernel"]
        verbose = self.config.get("verbose", False)
        
        all_detections = []
        total_score = 0
        
        # Run all checks
        vollog.info("Checking for sandbox processes...")
        proc_score, proc_detections = self._check_processes(kernel_module_name)
        all_detections.extend(proc_detections)
        total_score += proc_score
        
        vollog.info("Checking for sandbox DLLs...")
        dll_score, dll_detections = self._check_dlls(kernel_module_name)
        all_detections.extend(dll_detections)
        total_score += dll_score
        
        vollog.info("Checking system information...")
        sys_score, sys_detections = self._check_system_info(kernel_module_name)
        all_detections.extend(sys_detections)
        total_score += sys_score
        
        vollog.info("Checking for VM drivers...")
        drv_score, drv_detections = self._check_drivers(kernel_module_name)
        all_detections.extend(drv_detections)
        total_score += drv_score
        
        # Calculate verdict
        verdict, confidence = self._calculate_verdict(total_score, len(all_detections))
        
        # Yield summary
        yield (0, (
            "SUMMARY",
            verdict,
            f"Score: {total_score} | Detections: {len(all_detections)}",
            confidence,
            ""
        ))
        
        yield (0, ("", "", "", "", ""))
        
        # Yield detailed detections if verbose or if detections found
        if verbose or all_detections:
            for detection in all_detections:
                yield (0, (
                    detection.get('type', 'N/A'),
                    detection.get('indicator', 'N/A'),
                    detection.get('description', 'N/A'),
                    detection.get('severity', 'N/A'),
                    detection.get('info', 'N/A')
                ))
    
    def run(self):
        return renderers.TreeGrid(
            [
                ("Detection Type", str),
                ("Indicator", str),
                ("Description", str),
                ("Severity", str),
                ("Additional Info", str)
            ],
            self._generator(),
        )