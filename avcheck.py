import logging
from typing import List, Dict
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, filescan, svcscan, dlllist

vollog = logging.getLogger(__name__)

class AVCheck(interfaces.plugins.PluginInterface):
    """Detects installed antivirus products and their detection history from memory."""
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)
    
    # Comprehensive AV process names (80+ processes)
    AV_PROCESSES = [
        # Windows Defender
        'msmpeng.exe', 'msseces.exe', 'nissrv.exe', 'nigsrv.exe', 'mpcmdrun.exe',
        'securityhealthservice.exe', 'securityhealthsystray.exe', 'smartscreen.exe',
        
        # Kaspersky
        'avp.exe', 'avpui.exe', 'kavtray.exe', 'klnagent.exe', 'kavfswh.exe',
        'kavfswp.exe', 'kavfsgt.exe', 'klwtblfs.exe', 'kavstart.exe',
        
        # AVG
        'avgui.exe', 'avgsvc.exe', 'avgwdsvc.exe', 'avgidsagent.exe', 'avgtoolssvc.exe',
        'avgrsx.exe', 'avgcsrvx.exe', 'avgemcx.exe', 'avgnt.exe',
        
        # Avira
        'avguard.exe', 'avgnt.exe', 'sched.exe', 'avshadow.exe', 'avwebgrd.exe',
        
        # Bitdefender
        'bdagent.exe', 'bdservicehost.exe', 'updatesrv.exe', 'vsserv.exe',
        'bdredline.exe', 'epag.exe', 'epintegrationservice.exe', 'bdwtxag.exe',
        
        # McAfee
        'mcshield.exe', 'mcuicnt.exe', 'mfemms.exe', 'mfeann.exe', 'mcods.exe',
        'masvc.exe', 'mfevtps.exe', 'mfeatp.exe', 'modsysreport.exe', 'mcinfo.exe',
        
        # Norton/Symantec
        'nortonsecurity.exe', 'ns.exe', 'ccsvchst.exe', 'nsbu.exe', 'wrsa.exe',
        'rtvscan.exe', 'symcorpui.exe', 'nsinfo.exe', 'nswscsvc.exe',
        
        # ESET
        'ekrn.exe', 'egui.exe', 'esetservice.exe', 'epfwwfp.exe', 'eprotecttray.exe',
        'eguiproxy.exe', 'ecleaner.exe', 'esetonlinescanner.exe',
        
        # Malwarebytes
        'mbam.exe', 'mbamservice.exe', 'mbamtray.exe', 'mbampt.exe', 'mbae.exe',
        'mbaeapi.exe', 'mbaemapi.exe', 'mbae64.exe',
        
        # Sophos
        'savservice.exe', 'sophoshealth.exe', 'savadminservice.exe', 'almon.exe',
        'swi_service.exe', 'swc_service.exe', 'hmpalert.exe', 'sophosfilescanner.exe',
        
        # Trend Micro
        'pccntmon.exe', 'tmbmsrv.exe', 'tmproxy.exe', 'ntrtscan.exe', 'tmccsf.exe',
        'tmlistensvc.exe', 'tmlisten.exe', 'ofcservice.exe', 'pcclient.exe',
        
        # ClamAV
        'clamtray.exe', 'freshclam.exe', 'clamd.exe', 'clamav.exe', 'clamwin.exe',
        
        # Avast
        'ashdisp.exe', 'avastsvc.exe', 'avastui.exe', 'aswengsrv.exe', 'afwserv.exe',
        'avastbrowserui.exe', 'ngservice.exe', 'aswidsagent.exe',
        
        # Comodo
        'cmdagent.exe', 'cfp.exe', 'cistray.exe', 'cavwp.exe', 'cis.exe',
        
        # F-Secure
        'fsav32.exe', 'fshoster32.exe', 'fsdfwd.exe', 'fssm32.exe', 'fsguiexe.exe',
        
        # Panda
        'psimreal.exe', 'pavfnsvr.exe', 'pavsrv51.exe', 'psimsvc.exe', 'apvxdwin.exe',
        
        # G Data
        'avk.exe', 'avkwctl.exe', 'avgnt.exe', 'avkservice.exe', 'avkproxy.exe',
        
        # Webroot
        'wrsa.exe', 'wrsvc.exe', 'webrootspy.exe',
        
        # Dr.Web
        'drweb32w.exe', 'drwebupw.exe', 'spidernt.exe', 'drwebscd.exe',
        
        # Emsisoft
        'a2service.exe', 'a2guard.exe', 'a2start.exe', 'emsisoft.exe',
        
        # K7
        'k7tsecurity.exe', 'k7avwsvc.exe', 'k7rtscan.exe', 'k7fwhlpr.exe',
        
        # Quick Heal
        'mssecsvc.exe', 'quhlpsvc.exe', 'onlinescan.exe', 'qhwscsvc.exe',
        
        # ZoneAlarm
        'zonealarm.exe', 'zlclient.exe', 'vsmon.exe', 'zapro.exe',
        
        # 360 Total Security
        '360tray.exe', '360sd.exe', '360rps.exe', 'zhudongfangyu.exe',
        
        # Baidu Antivirus
        'baidu.exe', 'baiduav.exe', 'baidusafetray.exe',
    ]
    
    # AV service names (30+ services)
    AV_SERVICES = [
        'WinDefend', 'SecurityHealthService', 'WdNisSvc', 'Sense',  # Defender
        'AVP', 'KAVFS', 'KAVFSSLP', 'klnagent',  # Kaspersky
        'AVGSvc', 'avgwd', 'AVGIDSAgent',  # AVG
        'AntiVirService', 'AntiVirSchedulerService', 'Avira',  # Avira
        'VSSERV', 'bdredline', 'EPProtectedService',  # Bitdefender
        'McShield', 'mcoemcpy', 'mfevtp', 'mfefire',  # McAfee
        'SepMasterService', 'Norton', 'ccSetMgr',  # Norton
        'ekrn', 'epfw', 'epfwwfp',  # ESET
        'MBAMService', 'mbamtray', 'MBAMProtection',  # Malwarebytes
        'SAVService', 'Sophos', 'SophosAgent',  # Sophos
        'TmListen', 'ntrtscan', 'tmccsf',  # Trend Micro
        'avast!', 'aswbidsagent', 'AvastSvc',  # Avast
        'CmdAgent', 'COMODO',  # Comodo
    ]
    
    # Comprehensive detection/quarantine patterns (80+ patterns)
    DETECTION_PATTERNS = [
        # Generic patterns
        'detection.log', 'quarantine', 'threats.log', 'detections.db', 'detection_history',
        'viruslog', 'scanlog', 'infections.log', 'threat_log', 'avlog', 'infected',
        'malware', 'virus', 'trojan', 'suspicious', 'blocked', 'alert',
        
        # Windows Defender
        'mplog-', 'detection.log', 'protectionlog', 'mpasbase.vdm', 'mpenginedb',
        'support\\mpdetection', 'resourcedata.bin', 'detectionshistory',
        
        # Kaspersky
        'klreport', 'klsysinfo', 'avp_log', 'updater_log', 'events.db', 'kl_traces',
        'kavbase', 'klquarantine', 'klscan', 'kl_infected',
        
        # McAfee
        'accessprotectionlog', 'bufferlog', 'ondemandlog', 'oaplog', 'scanlog.txt',
        'mcshield_log', 'quarantine.dat', 'detection.dat',
        
        # Symantec/Norton
        'seclog.log', 'symantec_av.log', 'avlog.txt', 'quarantine.db', 'vslog',
        'virusscan.log', 'av_activity.log', 'threats.log',
        
        # Bitdefender
        'bdservicehost.log', 'update.log', 'scan.log', 'product_data.db',
        'quarantine.qdb', 'infections.dat',
        
        # ESET
        'emlarchive.dat', 'emlproxy.dat', 'virlog.dat', 'action.dat', 'scanner.log',
        
        # Trend Micro
        'pattern.log', 'scan.log', 'vscan.log', 'pccnt.log', 'trend_log',
        
        # Malwarebytes
        'mbam-log-', 'service.log', 'protection-log', 'scanlog', 'quarantine.db',
        
        # AVG
        'avgui.log', 'avgsvc.log', 'avgupdate.log', 'avgcc.log', 'avgidp.log',
        
        # Avast
        'avast_log', 'ashwebsv.log', 'ashmaisv.log', 'avast.log', 'virusdb',
        
        # Sophos
        'sav.txt', 'sophosav.log', 'sav_log', 'almon.log', 'detection.xml',
        
        # Comodo
        'cis.log', 'cfp.log', 'detection_log', 'cmdagent.log',
        
        # Threat types
        'backdoor', 'rootkit', 'worm', 'spyware', 'ransomware', 'adware',
        
        # Generic database files
        '.qdb', '.vdb', '.avc', '.ndb', '.hdb', '.mdb', '.cdb', '.ldb',
        'signatures', 'definitions', 'updates.db', 'cache.db',
    ]
    
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel module",
                architectures=["Intel32", "Intel64"],
            ),
        ]
    
    def _detect_av_processes(self, kernel_module_name: str) -> List[Dict]:
        """Detect running antivirus processes."""
        av_procs = []
        
        for proc in pslist.PsList.list_processes(self.context, kernel_module_name):
            try:
                proc_name = proc.ImageFileName.cast(
                    "string",
                    max_length=proc.ImageFileName.vol.count,
                    errors="replace"
                ).lower()
                
                if any(av_proc.lower() in proc_name for av_proc in self.AV_PROCESSES):
                    proc_pid = proc.UniqueProcessId
                    proc_ppid = proc.InheritedFromUniqueProcessId
                    
                    # Try to get full path
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
                    
                    # Try to get command line
                    try:
                        if peb and process_params:
                            cmdline = process_params.CommandLine.get_string()
                            cmdline_str = cmdline if cmdline else "N/A"
                        else:
                            cmdline_str = "N/A"
                    except Exception:
                        cmdline_str = "N/A"
                    
                    av_procs.append({
                        'name': proc_name,
                        'pid': proc_pid,
                        'ppid': proc_ppid,
                        'path': proc_path,
                        'cmdline': cmdline_str
                    })
                    
            except Exception as e:
                vollog.debug(f"Error processing process: {e}")
                continue
        
        return av_procs
    
    def _detect_av_services(self) -> List[Dict]:
        """Detect antivirus-related Windows services."""
        av_services = []
        
        try:
            # Use the correct method for listing services
            for service in svcscan.SvcScan.list_svcs(
                context=self.context,
                layer_name=self.config["kernel"],
                symbol_table=self.config["kernel"]
            ):
                try:
                    service_name = service.get_name()
                    
                    # Check if service name matches AV patterns
                    if any(av_svc.lower() in service_name.lower() for av_svc in self.AV_SERVICES):
                        display_name = service.get_display_name()
                        state = service.get_state()
                        binary_path = service.get_binary_path()
                        
                        av_services.append({
                            'name': service_name,
                            'display': display_name,
                            'state': state,
                            'binary': binary_path
                        })
                        
                except Exception as e:
                    vollog.debug(f"Error processing service: {e}")
                    continue
                    
        except Exception as e:
            vollog.debug(f"Service scan unavailable: {e}")
        
        return av_services
    
    def _detect_av_dlls(self, kernel_module_name: str) -> List[Dict]:
        """Detect AV-related DLLs loaded in processes."""
        av_dlls = []
        dll_patterns = [
            'defender', 'kaspersky', 'avg', 'avira', 'bitdefender', 'mcafee',
            'norton', 'symantec', 'eset', 'malwarebytes', 'sophos', 'trend',
            'avast', 'comodo', 'fsecure', 'panda', 'gdata', 'webroot',
            'scan', 'antivirus', 'av', 'guard', 'shield', 'protect'
        ]
        
        seen_dlls = set()
        
        try:
            for proc in pslist.PsList.list_processes(self.context, kernel_module_name):
                try:
                    proc_name = proc.ImageFileName.cast(
                        "string",
                        max_length=proc.ImageFileName.vol.count,
                        errors="replace"
                    )
                    
                    for dll in proc.load_order_modules():
                        try:
                            dll_name = dll.BaseDllName.get_string().lower()
                            dll_path = dll.FullDllName.get_string()
                            
                            if any(pattern in dll_name for pattern in dll_patterns):
                                dll_key = f"{dll_name}|{dll_path}"
                                if dll_key not in seen_dlls:
                                    seen_dlls.add(dll_key)
                                    av_dlls.append({
                                        'name': dll_name,
                                        'path': dll_path,
                                        'process': proc_name,
                                        'pid': proc.UniqueProcessId,
                                        'base': format_hints.Hex(dll.DllBase)
                                    })
                                    
                        except Exception:
                            continue
                            
                except Exception:
                    continue
                    
        except Exception as e:
            vollog.debug(f"Error scanning DLLs: {e}")
        
        return av_dlls
    
    def _detect_av_files(self) -> List[Dict]:
        """Detect antivirus-related files including detection logs and quarantine."""
        av_files = []
        
        try:
            # Use filescan to find AV-related files
            for file_obj in filescan.FileScan.scan_files(
                self.context,
                self.config["kernel"]
            ):
                try:
                    file_name = file_obj.FileName.String
                    file_name_lower = file_name.lower()
                    
                    # Check if file matches AV patterns (stricter filtering)
                    is_detection_file = any(
                        pattern.lower() in file_name_lower 
                        for pattern in self.DETECTION_PATTERNS
                    )
                    
                    # Check for AV vendor directories (stricter)
                    av_directories = [
                        'windows defender', 'kaspersky', 'mcafee', 'norton', 'symantec', 
                        'bitdefender', 'eset', 'malwarebytes', 'sophos', 'trend micro',
                        'avast', 'avg', 'avira', 'comodo', 'fsecure', 'panda', 'gdata',
                        'webroot', 'quarantine', 'virus', 'threat', 'infected'
                    ]
                    
                    is_av_directory = any(av_dir in file_name_lower for av_dir in av_directories)
                    
                    # Exclude common false positives
                    false_positives = ['windowsupdate.log', 'iconcache.db', 'thumbs.db', 
                                     'prefetch', 'recent', 'cookies']
                    is_false_positive = any(fp in file_name_lower for fp in false_positives)
                    
                    if (is_detection_file or is_av_directory) and not is_false_positive:
                        # Determine file type with more granularity
                        if any(p in file_name_lower for p in ['quarantine', 'infected', 'malware']):
                            file_type = "Quarantine"
                        elif any(p in file_name_lower for p in ['detection', 'threat']):
                            file_type = "Detection Log"
                        elif 'scan' in file_name_lower:
                            file_type = "Scan Log"
                        elif any(p in file_name_lower for p in ['mpenginedb', 'signature', 'definition']):
                            file_type = "Signature DB"
                        else:
                            file_type = "AV Artifact"
                        
                        # Extract threat information from filename if present
                        threat_indicators = []
                        threat_keywords = ['trojan', 'virus', 'malware', 'ransomware', 
                                         'backdoor', 'rootkit', 'worm', 'spyware']
                        
                        for keyword in threat_keywords:
                            if keyword in file_name_lower:
                                threat_indicators.append(keyword.capitalize())
                        
                        threat_info = ', '.join(threat_indicators) if threat_indicators else 'N/A'
                        
                        av_files.append({
                            'path': file_name,
                            'type': file_type,
                            'threats': threat_info,
                            'offset': file_obj.vol.offset
                        })
                        
                except Exception as e:
                    vollog.debug(f"Error processing file: {e}")
                    continue
                    
        except Exception as e:
            vollog.debug(f"Error in filescan: {e}")
        
        return av_files
    
    def _identify_av_vendor(self, proc_name: str, proc_path: str) -> str:
        """Identify the AV vendor from process name/path."""
        proc_lower = (proc_name + ' ' + proc_path).lower()
        
        vendor_checks = [
            (['defender', 'msmpeng', 'msseces', 'windowsdefender', 'securityhealth'], 'Windows Defender'),
            (['kaspersky', 'avp', 'kav', 'klnagent'], 'Kaspersky'),
            (['avg'], 'AVG'),
            (['avira', 'avgnt', 'avguard'], 'Avira'),
            (['bitdefender', 'bdagent', 'vsserv'], 'Bitdefender'),
            (['mcafee', 'mcshield', 'mfemms'], 'McAfee'),
            (['norton', 'symantec', 'ccsvchst', 'nsbu'], 'Norton/Symantec'),
            (['eset', 'ekrn', 'egui'], 'ESET'),
            (['malwarebytes', 'mbam'], 'Malwarebytes'),
            (['sophos', 'savservice'], 'Sophos'),
            (['trendmicro', 'trend', 'pccntmon', 'tmbmsrv'], 'Trend Micro'),
            (['clamav', 'clam'], 'ClamAV'),
            (['avast', 'aswengsrv'], 'Avast'),
            (['comodo', 'cmdagent', 'cfp'], 'Comodo'),
            (['f-secure', 'fsav', 'fshoster'], 'F-Secure'),
            (['panda', 'psimreal', 'pavfnsvr'], 'Panda'),
            (['gdata', 'g data', 'avk'], 'G Data'),
            (['webroot', 'wrsa'], 'Webroot'),
            (['drweb', 'dr.web', 'spidernt'], 'Dr.Web'),
            (['emsisoft', 'a2service', 'a2guard'], 'Emsisoft'),
            (['k7', 'k7tsecurity'], 'K7'),
            (['quickheal', 'quick heal', 'mssecsvc'], 'Quick Heal'),
            (['zonealarm', 'vsmon'], 'ZoneAlarm'),
            (['360', 'qihu'], '360 Total Security'),
            (['baidu'], 'Baidu Antivirus'),
        ]
        
        for keywords, vendor_name in vendor_checks:
            if any(keyword in proc_lower for keyword in keywords):
                return vendor_name
        
        return "Unknown AV Product"
    
    def _generator(self):
        kernel_module_name = self.config["kernel"]
        
        # Collect all data
        av_procs = self._detect_av_processes(kernel_module_name)
        av_services = self._detect_av_services()
        av_dlls = self._detect_av_dlls(kernel_module_name)
        av_files = self._detect_av_files()
        
        # Get detected vendors
        detected_vendors = set()
        if av_procs:
            for proc in av_procs:
                vendor = self._identify_av_vendor(proc['name'], proc['path'])
                detected_vendors.add(vendor)
        
        # EVERY yield must have exactly 4 values
        yield (0, ("=" * 80, "", "", ""))
        yield (0, ("ANTIVIRUS DETECTION RESULTS", "", "", ""))
        yield (0, ("=" * 80, "", "", ""))
        yield (0, ("", "", "", ""))
        
        # Detected Products
        if detected_vendors:
            yield (0, ("Detected AV Products:", "", "", ""))
            for vendor in sorted(detected_vendors):
                yield (0, (f"  * {vendor}", "", "", ""))
            yield (0, ("", "", "", ""))
        
        # Running Processes
        if av_procs:
            yield (0, ("Running AV Processes:", "", "", ""))
            for proc in av_procs:
                vendor = self._identify_av_vendor(proc['name'], proc['path'])
                yield (0, (
                    f"  * {proc['name']}",
                    f"PID: {proc['pid']} | PPID: {proc['ppid']}",
                    f"Vendor: {vendor}",
                    proc['path']
                ))
            yield (0, ("", "", "", ""))
        else:
            yield (0, ("Running AV Processes:", "", "", ""))
            yield (0, ("  * No AV processes detected", "", "", ""))
            yield (0, ("", "", "", ""))
        
        # Services
        if av_services:
            yield (0, ("AV Services:", "", "", ""))
            for svc in av_services:
                yield (0, (
                    f"  * {svc['name']}",
                    f"State: {svc['state']}",
                    f"Display: {svc['display']}",
                    svc['binary']
                ))
            yield (0, ("", "", "", ""))
        
        # DLLs (limited output)
        if av_dlls:
            yield (0, ("AV DLLs (Top 15):", "", "", ""))
            for dll in av_dlls[:15]:
                yield (0, (
                    f"  * {dll['name']}",
                    f"Process: {dll['process']} (PID: {dll['pid']})",
                    f"Base: {dll['base']}",
                    dll['path']
                ))
            if len(av_dlls) > 15:
                yield (0, (f"  ... and {len(av_dlls) - 15} more DLLs", "", "", ""))
            yield (0, ("", "", "", ""))
        
        # Detection Files (categorized) - ALWAYS SHOW IF THERE ARE FILES
        if av_files:
            quarantine = [f for f in av_files if f['type'] == 'Quarantine']
            detection = [f for f in av_files if f['type'] == 'Detection Log']
            scan = [f for f in av_files if f['type'] == 'Scan Log']
            signature = [f for f in av_files if f['type'] == 'Signature DB']
            other = [f for f in av_files if f['type'] == 'AV Artifact']
            
            if quarantine:
                yield (0, ("Quarantine Files:", "", "", ""))
                for f in quarantine:
                    threat_display = f" [Threats: {f['threats']}]" if f['threats'] != 'N/A' else ""
                    yield (0, (
                        f"  * {f['type']}",
                        f"Offset: 0x{f['offset']:x}",
                        threat_display,
                        f['path']
                    ))
                yield (0, ("", "", "", ""))
            
            if detection:
                yield (0, ("Detection Logs:", "", "", ""))
                for f in detection:
                    threat_display = f" [Threats: {f['threats']}]" if f['threats'] != 'N/A' else ""
                    yield (0, (
                        f"  * {f['type']}",
                        f"Offset: 0x{f['offset']:x}",
                        threat_display,
                        f['path']
                    ))
                yield (0, ("", "", "", ""))
            
            if scan:
                yield (0, ("Scan Logs:", "", "", ""))
                for f in scan[:10]:
                    yield (0, (
                        f"  * {f['type']}",
                        f"Offset: 0x{f['offset']:x}",
                        "",
                        f['path']
                    ))
                if len(scan) > 10:
                    yield (0, (f"  ... and {len(scan) - 10} more scan logs", "", "", ""))
                yield (0, ("", "", "", ""))
            
            if signature:
                yield (0, ("Signature Databases:", "", "", ""))
                for f in signature[:5]:
                    yield (0, (
                        f"  * {f['type']}",
                        f"Offset: 0x{f['offset']:x}",
                        "",
                        f['path']
                    ))
                if len(signature) > 5:
                    yield (0, (f"  ... and {len(signature) - 5} more signatures", "", "", ""))
                yield (0, ("", "", "", ""))
            
            if other:
                yield (0, ("Other AV Artifacts:", "", "", ""))
                for f in other[:10]:
                    yield (0, (
                        f"  * {f['type']}",
                        f"Offset: 0x{f['offset']:x}",
                        "",
                        f['path']
                    ))
                if len(other) > 10:
                    yield (0, (f"  ... and {len(other) - 10} more artifacts", "", "", ""))
                yield (0, ("", "", "", ""))
        else:
            yield (0, ("Detection Files:", "", "", ""))
            yield (0, ("  * No detection files found", "", "", ""))
            yield (0, ("", "", "", ""))
        
        # Summary
        yield (0, ("=" * 80, "", "", ""))
        total = len(av_procs) + len(av_services) + len(av_dlls) + len(av_files)
        if total > 0:
            yield (0, (f"SUMMARY: {total} Total Indicators", "", "", ""))
            yield (0, (f"  Processes: {len(av_procs)} | Services: {len(av_services)} | DLLs: {len(av_dlls)} | Files: {len(av_files)}", "", "", ""))
        else:
            yield (0, ("No antivirus indicators found", "", "", ""))
        yield (0, ("=" * 80, "", "", ""))
    
    def run(self):
        return renderers.TreeGrid(
            [
                ("Info", str),
                ("Details", str),
                ("Extra", str),
                ("Path", str),
            ],
            self._generator(),
        )