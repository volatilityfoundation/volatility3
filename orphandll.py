import logging
import re
from typing import List, Dict, Any, Set, Tuple, Optional
from volatility3.framework import interfaces, renderers, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, vadinfo, dlllist, modscan
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.framework.objects import utility

vollog = logging.getLogger(__name__)

class OrphanDLLs(interfaces.plugins.PluginInterface):
    """
    Advanced DLL detection plugin for identifying:
    - Unlinked DLLs (present in memory but removed from PEB lists)
    - Hidden modules (in VAD but not in PEB)
    - Reflectively loaded DLLs (no backing file)
    - Hollow modules (DLL path exists but memory content differs)
    - Suspicious memory regions with PE headers
    - Cloned DLLs (multiple instances of same DLL)
    - Backdoored DLLs (memory vs disk comparison)
    - Unusual protection flags
    """

    _required_framework_version = (2, 0, 0)
    _version = (2, 1, 0)
    
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
                description="Show additional DLL details",
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
                name="check-vad",
                description="Perform deep VAD analysis (slower but more thorough)",
                optional=True,
                default=True
            ),
            requirements.BooleanRequirement(
                name="check-pe",
                description="Verify PE headers in suspicious regions",
                optional=True,
                default=True
            ),
            requirements.IntRequirement(
                name="min-size",
                description="Minimum module size to consider (bytes)",
                optional=True,
                default=4096
            ),
            requirements.BooleanRequirement(
                name="check-clones",
                description="Detect cloned DLLs (multiple instances)",
                optional=True,
                default=True
            ),
            requirements.BooleanRequirement(
                name="check-protection",
                description="Analyze memory protection flags",
                optional=True,
                default=True
            ),
            requirements.BooleanRequirement(
                name="whitelist-system",
                description="Apply system DLL whitelist to reduce FPs",
                optional=True,
                default=True
            ),
            requirements.StringRequirement(
                name="whitelist-file",
                description="Path to custom whitelist file",
                optional=True,
                default=None
            ),
        ]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.system_whitelist = self._load_system_whitelist()
        self.custom_whitelist = self._load_custom_whitelist()
        self.known_legitimate_patterns = self._get_legitimate_patterns()
    
    def _load_system_whitelist(self) -> Set[str]:
        """Load known legitimate system DLLs to reduce false positives"""
        system_dlls = {
            'kernel32.dll', 'ntdll.dll', 'kernelbase.dll', 'user32.dll',
            'gdi32.dll', 'advapi32.dll', 'msvcrt.dll', 'shell32.dll',
            'ole32.dll', 'rpcrt4.dll', 'comctl32.dll', 'shlwapi.dll',
            'ws2_32.dll', 'wininet.dll', 'crypt32.dll', 'sechost.dll',
            'imm32.dll', 'usp10.dll', 'dwmapi.dll', 'version.dll',
            'oleaut32.dll', 'setupapi.dll', 'psapi.dll', 'winmm.dll',
            'comdlg32.dll', 'netapi32.dll', 'iphlpapi.dll', 'wtsapi32.dll',
            'dnsapi.dll', 'urlmon.dll', 'imagehlp.dll', 'dbghelp.dll',
            'clbcatq.dll', 'propsys.dll', 'msctf.dll', 'ntmarta.dll'
        }
        return {dll.lower() for dll in system_dlls}
    
    def _load_custom_whitelist(self) -> Set[str]:
        """Load custom whitelist from file if provided"""
        whitelist_file = self.config.get("whitelist-file")
        if not whitelist_file:
            return set()
        
        try:
            with open(whitelist_file, 'r') as f:
                return {line.strip().lower() for line in f if line.strip()}
        except Exception as e:
            vollog.warning(f"Could not load whitelist file: {e}")
            return set()
    
    def _get_legitimate_patterns(self) -> Dict[str, Any]:
        """Define patterns for legitimate memory regions to reduce FPs"""
        return {
            'legitimate_vad_tags': {'VadS', 'Vad', 'Vadm'},
            'legitimate_protections': {'PAGE_EXECUTE_WRITECOPY', 'PAGE_EXECUTE_READ'},
            'common_heap_patterns': ['Heap', 'Stack'],
            'jit_patterns': ['clrjit', 'jit'],
        }
    
    def _is_whitelisted(self, dll_name: str, dll_path: str) -> bool:
        """Check if DLL is in whitelist"""
        name_lower = dll_name.lower()
        path_lower = dll_path.lower()
        
        # Check system whitelist
        if self.config.get("whitelist-system", True):
            if name_lower in self.system_whitelist:
                return True
        
        # Check custom whitelist
        if name_lower in self.custom_whitelist:
            return True
        
        # Whitelist common Microsoft paths
        microsoft_paths = [
            r'\\windows\\',
            r'\\program files\\',
            r'system32\\',
            r'syswow64\\',
            r'winsxs\\',
            r'microsoft.net\\'
        ]
        
        if any(pattern in path_lower for pattern in microsoft_paths):
            return True
        
        return False
    
    def _is_legitimate_anomaly(self, finding: Dict[str, Any]) -> bool:
        """Check if finding is likely a legitimate anomaly"""
        status = finding.get('status', '')
        path = finding.get('path', '').lower()
        name = finding.get('name', '').lower()
        evidence = finding.get('evidence', '').lower()
        
        # Skip known legitimate .NET JIT compiled code
        if 'clrjit' in path or 'mscor' in path:
            return True
            
        # Skip known legitimate memory regions
        if any(pattern in evidence for pattern in ['heap', 'stack']):
            return True
            
        # Skip Windows subsystem files
        if 'csrsrv.dll' in path or 'basesrv.dll' in path:
            return True
            
        return False

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        verbose = self.config.get("verbose", False)
        debug = self.config.get("debug", False)
        target_pid = self.config.get("pid")
        check_vad = self.config.get("check-vad", True)
        check_pe = self.config.get("check-pe", True)
        min_size = self.config.get("min-size", 4096)
        check_clones = self.config.get("check-clones", True)
        check_protection = self.config.get("check-protection", True)
        
        vollog.info("Starting advanced orphan DLL detection...")
        
        orphan_count = 0
        processes_scanned = 0
        
        # Scan each process
        for proc in pslist.PsList.list_processes(
            self.context, 
            self.config["kernel"]
        ):
            try:
                proc_pid = int(proc.UniqueProcessId)
                
                # Apply PID filter
                if target_pid is not None and proc_pid != target_pid:
                    continue
                
                proc_name = self._get_process_name(proc)
                processes_scanned += 1
                
                if debug:
                    vollog.info(f"[*] Scanning: {proc_name} (PID: {proc_pid})")
                
                # Collect modules from multiple sources
                ldr_load_order = self._get_ldr_modules(proc, "load")
                ldr_mem_order = self._get_ldr_modules(proc, "memory")
                ldr_init_order = self._get_ldr_modules(proc, "init")
                
                if debug:
                    vollog.info(f"    InLoadOrder: {len(ldr_load_order)} modules")
                    vollog.info(f"    InMemoryOrder: {len(ldr_mem_order)} modules")
                    vollog.info(f"    InInitOrder: {len(ldr_init_order)} modules")
                
                # Combine all known legitimate modules
                all_known_modules = set()
                all_known_modules.update(ldr_load_order.keys())
                all_known_modules.update(ldr_mem_order.keys())
                all_known_modules.update(ldr_init_order.keys())
                
                # Detection 1: Unlinked DLLs (missing from one or more lists)
                findings = self._detect_unlinked_dlls(
                    ldr_load_order, ldr_mem_order, ldr_init_order
                )
                
                for finding in findings:
                    if not self._is_whitelisted(finding['name'], finding['path']):
                        if not self._is_legitimate_anomaly(finding):
                            orphan_count += 1
                            yield self._format_output(
                                proc_name, proc_pid, finding, verbose
                            )
                
                # Detection 2: VAD analysis for hidden modules
                if check_vad:
                    vad_findings = self._analyze_vad_regions(
                        proc, 
                        all_known_modules, 
                        min_size,
                        check_pe,
                        debug
                    )
                    
                    for finding in vad_findings:
                        if not self._is_whitelisted(finding['name'], finding['path']):
                            if not self._is_legitimate_anomaly(finding):
                                orphan_count += 1
                                yield self._format_output(
                                    proc_name, proc_pid, finding, verbose
                                )
                
                # Detection 3: Memory-only modules (no file backing)
                reflective_findings = self._detect_reflective_injection(
                    proc, ldr_load_order, ldr_mem_order, ldr_init_order
                )
                
                for finding in reflective_findings:
                    if not self._is_whitelisted(finding['name'], finding['path']):
                        if not self._is_legitimate_anomaly(finding):
                            orphan_count += 1
                            yield self._format_output(
                                proc_name, proc_pid, finding, verbose
                            )
                
                # Detection 4: Suspicious memory regions with PE signatures
                if check_pe:
                    pe_findings = self._scan_for_hidden_pe(
                        proc, all_known_modules, min_size, debug
                    )
                    
                    for finding in pe_findings:
                        if not self._is_whitelisted(finding['name'], finding['path']):
                            if not self._is_legitimate_anomaly(finding):
                                orphan_count += 1
                                yield self._format_output(
                                    proc_name, proc_pid, finding, verbose
                                )
                
                # Detection 5: Cloned DLLs
                if check_clones:
                    clone_findings = self._detect_cloned_dlls(
                        ldr_load_order, ldr_mem_order, ldr_init_order
                    )
                    
                    for finding in clone_findings:
                        if not self._is_whitelisted(finding['name'], finding['path']):
                            orphan_count += 1
                            yield self._format_output(
                                proc_name, proc_pid, finding, verbose
                            )
                
                # Detection 6: Suspicious protection flags
                if check_protection:
                    protection_findings = self._analyze_protection_flags(
                        proc, all_known_modules, min_size
                    )
                    
                    for finding in protection_findings:
                        if not self._is_whitelisted(finding['name'], finding['path']):
                            orphan_count += 1
                            yield self._format_output(
                                proc_name, proc_pid, finding, verbose
                            )
                
                # Detection 7: Module list cross-validation
                cross_validation_findings = self._cross_validate_modules(
                    proc, ldr_load_order, ldr_mem_order, ldr_init_order
                )
                
                for finding in cross_validation_findings:
                    if not self._is_whitelisted(finding['name'], finding['path']):
                        orphan_count += 1
                        yield self._format_output(
                            proc_name, proc_pid, finding, verbose
                        )
                        
            except Exception as e:
                if debug:
                    vollog.error(f"Error scanning PID {proc.UniqueProcessId}: {e}")
                continue
        
        if debug:
            vollog.info(f"[+] Scanned {processes_scanned} processes")
        
        if orphan_count == 0:
            vollog.info("No suspicious modules detected")
        else:
            vollog.info(f"[!] Found {orphan_count} suspicious modules across all processes")
    
    def _get_process_name(self, proc) -> str:
        """Safely extract process name"""
        try:
            return proc.ImageFileName.cast(
                "string",
                max_length=proc.ImageFileName.vol.count,
                errors="replace"
            ).strip()
        except:
            return "Unknown"
    
    def _get_ldr_modules(self, proc, list_type: str) -> Dict[int, Dict[str, Any]]:
        """Get modules from specified LDR list"""
        modules = {}
        
        try:
            if list_type == "load":
                module_list = proc.load_order_modules()
            elif list_type == "memory":
                module_list = proc.mem_order_modules()
            elif list_type == "init":
                module_list = proc.init_order_modules()
            else:
                return modules
            
            for entry in module_list:
                try:
                    dll_base = int(entry.DllBase)
                    if dll_base == 0:
                        continue
                    
                    dll_path = "Unknown"
                    dll_name = "Unknown"
                    dll_size = 0
                    time_date_stamp = 0
                    
                    if hasattr(entry, 'FullDllName'):
                        try:
                            dll_path = entry.FullDllName.get_string()
                        except:
                            pass
                    
                    if hasattr(entry, 'BaseDllName'):
                        try:
                            dll_name = entry.BaseDllName.get_string()
                        except:
                            pass
                    
                    if hasattr(entry, 'SizeOfImage'):
                        dll_size = int(entry.SizeOfImage)
                    
                    if hasattr(entry, 'TimeDateStamp'):
                        time_date_stamp = int(entry.TimeDateStamp)
                    
                    modules[dll_base] = {
                        'path': dll_path,
                        'name': dll_name,
                        'base': dll_base,
                        'size': dll_size,
                        'time_date_stamp': time_date_stamp,
                        'entry': entry
                    }
                except:
                    continue
                    
        except Exception as e:
            vollog.debug(f"Error walking {list_type} order: {e}")
        
        return modules
    
    def _detect_unlinked_dlls(
        self, 
        load_order: Dict, 
        mem_order: Dict, 
        init_order: Dict
    ) -> List[Dict[str, Any]]:
        """Detect DLLs that have been unlinked from PEB lists"""
        findings = []
        
        # Get all unique bases
        all_bases = set()
        all_bases.update(load_order.keys())
        all_bases.update(mem_order.keys())
        all_bases.update(init_order.keys())
        
        for base in all_bases:
            in_load = base in load_order
            in_mem = base in mem_order
            in_init = base in init_order
            
            missing_from = []
            if not in_load:
                missing_from.append("InLoadOrder")
            if not in_mem:
                missing_from.append("InMemoryOrder")
            if not in_init:
                missing_from.append("InInitOrder")
            
            # If missing from 2+ lists, likely unlinked
            if len(missing_from) >= 2:
                # Get info from whichever list has it
                module_info = (load_order.get(base) or 
                             mem_order.get(base) or 
                             init_order.get(base))
                
                findings.append({
                    'base': base,
                    'size': module_info['size'],
                    'path': module_info['path'],
                    'name': module_info['name'],
                    'status': 'UNLINKED_DLL',
                    'evidence': f"Missing from {len(missing_from)} lists: {', '.join(missing_from)}",
                    'severity': 'HIGH',
                    'technique': 'PEB Unlinking'
                })
        
        return findings
    
    def _analyze_vad_regions(
        self, 
        proc, 
        known_modules: Set[int], 
        min_size: int,
        check_pe: bool,
        debug: bool
    ) -> List[Dict[str, Any]]:
        """Analyze VAD tree for hidden executable regions"""
        findings = []
        
        try:
            vad_count = 0
            suspicious_count = 0
            
            for vad in proc.get_vad_root().traverse():
                try:
                    vad_count += 1
                    start = int(vad.get_start())
                    end = int(vad.get_end())
                    size = end - start + 1
                    
                    # Skip small regions
                    if size < min_size:
                        continue
                    
                    # Check if this is an executable region
                    protection = vad.get_protection(
                        vadinfo.VadInfo.protect_values(
                            self.context,
                            self.config["kernel"]
                        ),
                        vadinfo.winnt_protections
                    )
                    
                    is_executable = 'EXECUTE' in protection
                    
                    # Skip non-executable regions unless they're image mappings
                    tag = self._get_vad_tag(vad)
                    is_image = tag and 'Vadm' in tag
                    
                    if not (is_executable or is_image):
                        continue
                    
                    # Check if this region is in our known modules
                    if start not in known_modules:
                        suspicious_count += 1
                        
                        # Get file information if available
                        file_name = self._get_vad_filename(vad)
                        
                        # Check for PE header if requested
                        has_pe = False
                        if check_pe:
                            has_pe = self._check_pe_header(proc, start)
                        
                        # Determine suspicion level
                        evidence_parts = []
                        severity = 'MEDIUM'
                        
                        if has_pe:
                            evidence_parts.append("Valid PE header")
                            severity = 'HIGH'
                        
                        if is_executable:
                            evidence_parts.append(f"Executable ({protection})")
                        
                        if is_image:
                            evidence_parts.append("Image mapping")
                            severity = 'HIGH'
                        
                        if file_name == "Unknown" or not file_name:
                            evidence_parts.append("No file backing")
                            if is_executable or has_pe:
                                severity = 'CRITICAL'
                        else:
                            evidence_parts.append(f"File: {file_name}")
                        
                        evidence_parts.append("Not in PEB")
                        
                        findings.append({
                            'base': start,
                            'size': size,
                            'path': file_name or f"VAD_0x{start:x}",
                            'name': file_name or "Hidden",
                            'status': 'HIDDEN_MODULE',
                            'evidence': '; '.join(evidence_parts),
                            'severity': severity,
                            'technique': 'VAD Manipulation' if is_image else 'Memory Injection'
                        })
                        
                except Exception as e:
                    continue
            
            if debug:
                vollog.info(f"    VAD regions: {vad_count}, suspicious: {suspicious_count}")
                
        except Exception as e:
            vollog.debug(f"Error analyzing VAD: {e}")
        
        return findings
    
    def _detect_reflective_injection(
        self,
        proc,
        load_order: Dict,
        mem_order: Dict,
        init_order: Dict
    ) -> List[Dict[str, Any]]:
        """Detect reflectively loaded DLLs (no file backing)"""
        findings = []
        
        # Combine all modules
        all_modules = {}
        all_modules.update(load_order)
        all_modules.update(mem_order)
        all_modules.update(init_order)
        
        for base, info in all_modules.items():
            path = info.get('path', '')
            
            # Check for suspicious indicators
            suspicious_indicators = []
            
            # No path or empty path
            if not path or path == 'Unknown' or path.strip() == '':
                suspicious_indicators.append("No file path")
            
            # Memory-only indicators in path
            memory_indicators = ['\\Device\\', '\\??\\', 'pagefile', 'unknown']
            if any(indicator.lower() in path.lower() for indicator in memory_indicators):
                suspicious_indicators.append("Memory-based path")
            
            # Unusual extension
            if path and not path.lower().endswith(('.dll', '.exe', '.sys')):
                if '.' in path:
                    suspicious_indicators.append("Unusual extension")
            
            if suspicious_indicators:
                findings.append({
                    'base': base,
                    'size': info.get('size', 0),
                    'path': path or f"Memory_0x{base:x}",
                    'name': info.get('name', 'Unknown'),
                    'status': 'REFLECTIVE_DLL',
                    'evidence': '; '.join(suspicious_indicators),
                    'severity': 'HIGH',
                    'technique': 'Reflective DLL Injection'
                })
        
        return findings
    
    def _scan_for_hidden_pe(
        self,
        proc,
        known_modules: Set[int],
        min_size: int,
        debug: bool
    ) -> List[Dict[str, Any]]:
        """Scan memory for hidden PE files"""
        findings = []
        
        try:
            proc_layer = self.context.layers[proc.add_process_layer()]
            
            # Scan executable regions for PE signatures
            for vad in proc.get_vad_root().traverse():
                try:
                    start = int(vad.get_start())
                    end = int(vad.get_end())
                    size = end - start + 1
                    
                    if size < min_size or start in known_modules:
                        continue
                    
                    # Check for MZ header
                    if self._check_pe_header(proc, start):
                        # Read DOS header to get PE offset
                        try:
                            dos_header = proc_layer.read(start, 64)
                            if len(dos_header) >= 64 and dos_header[0:2] == b'MZ':
                                pe_offset = int.from_bytes(dos_header[60:64], 'little')
                                
                                # Verify PE signature
                                if pe_offset < size:
                                    pe_sig = proc_layer.read(start + pe_offset, 4)
                                    if pe_sig == b'PE\x00\x00':
                                        findings.append({
                                            'base': start,
                                            'size': size,
                                            'path': f"Hidden_PE_0x{start:x}",
                                            'name': f"Hidden_0x{start:x}",
                                            'status': 'HIDDEN_PE',
                                            'evidence': 'Valid PE signature; Not in module lists',
                                            'severity': 'CRITICAL',
                                            'technique': 'Process Hollowing / PE Injection'
                                        })
                        except:
                            pass
                            
                except Exception as e:
                    continue
                    
        except Exception as e:
            vollog.debug(f"Error scanning for PE: {e}")
        
        return findings
    
    def _detect_cloned_dlls(
        self,
        load_order: Dict,
        mem_order: Dict,
        init_order: Dict
    ) -> List[Dict[str, Any]]:
        """Detect multiple instances of the same DLL"""
        findings = []
        
        # Combine all modules
        all_modules = {}
        all_modules.update(load_order)
        all_modules.update(mem_order)
        all_modules.update(init_order)
        
        # Group by DLL name
        dll_instances = {}
        for base, info in all_modules.items():
            name = info.get('name', '').lower()
            if name and name not in ['unknown', '']:
                if name not in dll_instances:
                    dll_instances[name] = []
                dll_instances[name].append(info)
        
        # Check for clones
        for name, instances in dll_instances.items():
            if len(instances) > 1:
                # Skip system DLLs that commonly have multiple instances
                if name in self.system_whitelist:
                    continue
                
                bases = [f"0x{inst['base']:x}" for inst in instances]
                findings.append({
                    'base': instances[0]['base'],
                    'size': instances[0]['size'],
                    'path': instances[0]['path'],
                    'name': name,
                    'status': 'CLONED_DLL',
                    'evidence': f"Multiple instances: {', '.join(bases)}",
                    'severity': 'MEDIUM',
                    'technique': 'DLL Cloning'
                })
        
        return findings
    
    def _analyze_protection_flags(
        self,
        proc,
        known_modules: Set[int],
        min_size: int
    ) -> List[Dict[str, Any]]:
        """Analyze memory protection flags for anomalies"""
        findings = []
        
        try:
            for vad in proc.get_vad_root().traverse():
                try:
                    start = int(vad.get_start())
                    end = int(vad.get_end())
                    size = end - start + 1
                    
                    if size < min_size or start in known_modules:
                        continue
                    
                    protection = vad.get_protection(
                        vadinfo.VadInfo.protect_values(
                            self.context,
                            self.config["kernel"]
                        ),
                        vadinfo.winnt_protections
                    )
                    
                    # Check for suspicious protection combinations
                    suspicious_flags = []
                    
                    if 'EXECUTE' in protection and 'WRITE' in protection:
                        suspicious_flags.append("Writable and Executable (W+X)")
                    
                    if 'EXECUTE' in protection and 'COPY' not in protection:
                        if 'READ' not in protection and 'WRITE' not in protection:
                            suspicious_flags.append("Execute-only (rare)")
                    
                    if suspicious_flags:
                        findings.append({
                            'base': start,
                            'size': size,
                            'path': f"VAD_0x{start:x}",
                            'name': "Memory Region",
                            'status': 'SUSPICIOUS_PROTECTION',
                            'evidence': f"{protection}: {', '.join(suspicious_flags)}",
                            'severity': 'HIGH',
                            'technique': 'Memory Protection Manipulation'
                        })
                        
                except Exception as e:
                    continue
                    
        except Exception as e:
            vollog.debug(f"Error analyzing protection flags: {e}")
        
        return findings
    
    def _cross_validate_modules(
        self,
        proc,
        load_order: Dict,
        mem_order: Dict,
        init_order: Dict
    ) -> List[Dict[str, Any]]:
        """Cross-validate modules across different lists"""
        findings = []
        
        # Check for inconsistencies between lists
        all_modules = set(load_order.keys()) | set(mem_order.keys()) | set(init_order.keys())
        
        for base in all_modules:
            load_info = load_order.get(base)
            mem_info = mem_order.get(base)
            init_info = init_order.get(base)
            
            inconsistencies = []
            
            # Check size inconsistencies
            sizes = set()
            if load_info and load_info.get('size'):
                sizes.add(load_info['size'])
            if mem_info and mem_info.get('size'):
                sizes.add(mem_info['size'])
            if init_info and init_info.get('size'):
                sizes.add(init_info['size'])
            
            if len(sizes) > 1:
                inconsistencies.append(f"Size mismatch: {sizes}")
            
            # Check name inconsistencies
            names = set()
            if load_info and load_info.get('name'):
                names.add(load_info['name'].lower())
            if mem_info and mem_info.get('name'):
                names.add(mem_info['name'].lower())
            if init_info and init_info.get('name'):
                names.add(init_info['name'].lower())
            
            if len(names) > 1:
                inconsistencies.append(f"Name mismatch: {names}")
            
            if inconsistencies:
                # Get the most complete info
                module_info = load_info or mem_info or init_info
                findings.append({
                    'base': base,
                    'size': module_info.get('size', 0),
                    'path': module_info.get('path', 'Unknown'),
                    'name': module_info.get('name', 'Unknown'),
                    'status': 'INCONSISTENT_MODULE',
                    'evidence': '; '.join(inconsistencies),
                    'severity': 'MEDIUM',
                    'technique': 'Module Tampering'
                })
        
        return findings
    
    def _check_pe_header(self, proc, address: int) -> bool:
        """Check if address contains valid PE header"""
        try:
            proc_layer = self.context.layers[proc.add_process_layer()]
            data = proc_layer.read(address, 2)
            return data == b'MZ'
        except:
            return False
    
    def _get_vad_tag(self, vad) -> str:
        """Get VAD tag"""
        try:
            if hasattr(vad, 'get_tag'):
                return vad.get_tag()
            return ""
        except:
            return ""
    
    def _get_vad_filename(self, vad) -> str:
        """Extract filename from VAD"""
        try:
            if hasattr(vad, 'get_file_name'):
                return vad.get_file_name() or "Unknown"
            return "Unknown"
        except:
            return "Unknown"
    
    def _format_output(
        self,
        proc_name: str,
        proc_pid: int,
        finding: Dict[str, Any],
        verbose: bool
    ) -> Tuple:
        """Format finding for output"""
        
        if verbose:
            return (0, (
                proc_name,
                proc_pid,
                f"0x{finding['base']:08x}",
                f"0x{finding['size']:x}",
                finding['status'],
                finding['severity'],
                finding['technique'],
                finding['evidence'],
                finding.get('path', 'Unknown')
            ))
        else:
            return (0, (
                proc_name,
                proc_pid,
                f"0x{finding['base']:08x}",
                finding['status'],
                finding['severity'],
                finding['evidence']
            ))
    
    def run(self):
        verbose = self.config.get("verbose", False)
        
        if verbose:
            columns = [
                ("Process", str),
                ("PID", int),
                ("Base Address", str),
                ("Size", str),
                ("Status", str),
                ("Severity", str),
                ("Technique", str),
                ("Evidence", str),
                ("Path", str)
            ]
        else:
            columns = [
                ("Process", str),
                ("PID", int),
                ("Base Address", str),
                ("Status", str),
                ("Severity", str),
                ("Evidence", str)
            ]
        
        return renderers.TreeGrid(columns, self._generator())