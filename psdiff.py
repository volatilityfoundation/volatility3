import logging
from typing import List, Dict, Any, Tuple
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist
from volatility3.framework.objects import utility

vollog = logging.getLogger(__name__)

class PSDiff(interfaces.plugins.PluginInterface):
    """Compare process instances and detect anomalies"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel module",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.StringRequirement(
                name="p1",
                description="First process name or PID",
                optional=True,
                default=None
            ),
            requirements.StringRequirement(
                name="p2", 
                description="Second process name or PID",
                optional=True,
                default=None
            ),
            requirements.BooleanRequirement(
                name="show-all",
                description="Show all process comparisons",
                optional=True,
                default=False
            )
        ]
    
    def _generator(self):
        p1_target = self.config.get("p1")
        p2_target = self.config.get("p2")
        show_all = self.config.get("show-all", False)
        
        try:
            # Get all processes
            all_processes = self._get_all_processes()
            parent_names = self._build_parent_name_map(all_processes)
            expected_parents = self._build_expected_parents_map()
            
            if not p1_target and not p2_target:
                # General scanning mode - show comprehensive analysis
                yield from self._general_scanning_mode(all_processes, parent_names, expected_parents, show_all)
            elif p1_target and not p2_target:
                # Analyze single process
                yield from self._analyze_single_process(p1_target, all_processes, parent_names, expected_parents)
            elif p1_target and p2_target:
                # Compare two specific processes
                yield from self._compare_specific_processes(p1_target, p2_target, all_processes, parent_names, expected_parents)
            else:
                yield (0, ("ERROR", "Invalid parameters: -p2 requires -p1"))
            
        except Exception as e:
            yield (0, ("ERROR", f"Analysis failed: {str(e)}"))
    
    def _general_scanning_mode(self, all_processes: List[Dict], parent_names: Dict, expected_parents: Dict, show_all: bool) -> None:
        """Comprehensive analysis for general scanning"""
        yield (0, ("[COMPREHENSIVE PROCESS ANALYSIS]", ""))
        yield (0, (f"Total processes found: {len(all_processes)}", ""))
        yield (0, ("", ""))
        
        # 1. Show system overview
        yield from self._show_system_overview(all_processes, parent_names)
        
        # 2. Show suspicious parent-child relationships
        yield from self._show_suspicious_parents(all_processes, parent_names, expected_parents)
        
        # 3. Show processes with multiple instances
        yield from self._show_multiple_instances(all_processes, parent_names, expected_parents, show_all)
        
        # 4. Show unusual process patterns
        yield from self._show_unusual_patterns(all_processes, parent_names)
        
        yield (0, ("", ""))
        yield (0, ("[ANALYSIS COMPLETE]", "Use -p1 <process> for detailed analysis of specific processes"))
    
    def _show_system_overview(self, all_processes: List[Dict], parent_names: Dict) -> None:
        """Show system process overview"""
        yield (0, ("[SYSTEM OVERVIEW]", ""))
        
        # Count processes by session
        session_counts = {}
        for proc in all_processes:
            session = proc['session_id']
            session_counts[session] = session_counts.get(session, 0) + 1
        
        yield (0, (f"  Sessions active: {len(session_counts)}", ""))
        for session, count in sorted(session_counts.items()):
            yield (0, (f"    Session {session}: {count} processes", ""))
        
        # Count unique process names
        unique_names = set(proc['name'].lower() for proc in all_processes)
        yield (0, (f"  Unique process names: {len(unique_names)}", ""))
        
        # Show core system processes
        core_processes = ['system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'winlogon.exe']
        found_cores = []
        for proc in all_processes:
            if proc['name'].lower() in core_processes:
                parent_name = parent_names.get(proc['parent_pid'], "Unknown")
                found_cores.append(f"{proc['name']} (PID: {proc['pid']}, Parent: {parent_name})")
        
        if found_cores:
            yield (0, ("  Core system processes:", ""))
            for core in found_cores:
                yield (0, (f"    • {core}", ""))
        
        yield (0, ("", ""))
    
    def _show_suspicious_parents(self, all_processes: List[Dict], parent_names: Dict, expected_parents: Dict) -> None:
        """Show processes with suspicious parent relationships"""
        yield (0, ("[SUSPICIOUS PARENT-CHILD RELATIONSHIPS]", ""))
        
        suspicious_count = 0
        suspicious_relationships = []
        
        for proc in all_processes:
            current_parent = parent_names.get(proc['parent_pid'], "Unknown")
            expected_parent = expected_parents.get(proc['name'].lower())
            
            if expected_parent and current_parent.lower() != expected_parent.lower():
                suspicious_count += 1
                suspicious_relationships.append((
                    proc['name'],
                    proc['pid'],
                    current_parent,
                    expected_parent
                ))
        
        if suspicious_relationships:
            yield (0, (f"Found {suspicious_count} processes with unexpected parents:", ""))
            yield (0, ("", ""))
            
            for proc_name, pid, current_parent, expected_parent in suspicious_relationships:
                yield (0, (
                    f"  • {proc_name} (PID: {pid})", 
                    f"Current: {current_parent} | Expected: {expected_parent}"
                ))
        else:
            yield (0, ("No suspicious parent-child relationships detected", ""))
        
        yield (0, ("", ""))
    
    def _show_multiple_instances(self, all_processes: List[Dict], parent_names: Dict, expected_parents: Dict, show_all: bool) -> None:
        """Show processes with multiple instances and their differences"""
        yield (0, ("[PROCESSES WITH MULTIPLE INSTANCES]", ""))
        
        # Group processes by name
        process_groups = {}
        for proc in all_processes:
            name = proc['name']
            if name not in process_groups:
                process_groups[name] = []
            process_groups[name].append(proc)
        
        multi_instance_count = 0
        differences_found = 0
        
        for name, instances in process_groups.items():
            if len(instances) > 1:
                multi_instance_count += 1
                
                # Check if instances have differences
                has_differences = False
                for i in range(len(instances)):
                    for j in range(i + 1, len(instances)):
                        diffs = self._compare_processes(instances[i], instances[j], parent_names, expected_parents)
                        if diffs:
                            has_differences = True
                            break
                    if has_differences:
                        break
                
                if has_differences:
                    differences_found += 1
                    yield (0, (f"  • {name}: {len(instances)} instances - DIFFERENCES FOUND", ""))
                    
                    if show_all:
                        # Show detailed differences
                        yield from self._analyze_process_group(name, instances, parent_names, expected_parents)
                else:
                    yield (0, (f"  • {name}: {len(instances)} instances - No differences", ""))
        
        yield (0, ("", ""))
        yield (0, (f"Summary: {multi_instance_count} processes with multiple instances, {differences_found} with differences", ""))
        yield (0, ("", ""))
    
    def _show_unusual_patterns(self, all_processes: List[Dict], parent_names: Dict) -> None:
        """Show unusual process patterns"""
        yield (0, ("[UNUSUAL PATTERNS]", ""))
        
        unusual_patterns = []
        
        # Check for processes with unusual parents
        unusual_parents = [
            ('lsass.exe', ['explorer.exe', 'svchost.exe', 'winword.exe', 'excel.exe']),
            ('services.exe', ['explorer.exe', 'winword.exe', 'excel.exe']),
            ('wininit.exe', ['explorer.exe', 'services.exe']),
            ('csrss.exe', ['explorer.exe', 'services.exe']),
            ('smss.exe', ['explorer.exe', 'services.exe']),
        ]
        
        for proc_name, suspicious_parents in unusual_parents:
            for proc in all_processes:
                if proc['name'].lower() == proc_name.lower():
                    current_parent = parent_names.get(proc['parent_pid'], "").lower()
                    if current_parent in [p.lower() for p in suspicious_parents]:
                        unusual_patterns.append(f"{proc_name} (PID: {proc['pid']}) spawned by {current_parent}")
        
        # Check for orphaned processes (parent doesn't exist)
        orphaned = []
        existing_pids = set(proc['pid'] for proc in all_processes)
        for proc in all_processes:
            parent_pid = proc['parent_pid']
            if parent_pid not in existing_pids and parent_pid not in [0, 4] and parent_pid > 0:
                orphaned.append(f"{proc['name']} (PID: {proc['pid']}) - Parent PID {parent_pid} not found")
        
        if unusual_patterns:
            yield (0, ("Suspicious parent relationships:", ""))
            for pattern in unusual_patterns:
                yield (0, (f"  • {pattern}", ""))
            yield (0, ("", ""))
        
        if orphaned:
            yield (0, ("Orphaned processes:", ""))
            for orphan in orphaned:
                yield (0, (f"  • {orphan}", ""))
            yield (0, ("", ""))
        
        if not unusual_patterns and not orphaned:
            yield (0, ("No unusual patterns detected", ""))
        
        yield (0, ("", ""))
    
    def _analyze_process_group(self, name: str, instances: List[Dict], parent_names: Dict, expected_parents: Dict) -> List[Tuple]:
        """Analyze a group of processes with the same name"""
        results = []
        comparison_count = 0
        
        # Compare each unique pair
        for i in range(len(instances)):
            for j in range(i + 1, len(instances)):
                p1 = instances[i]
                p2 = instances[j]
                
                differences = self._compare_processes(p1, p2, parent_names, expected_parents)
                if differences:
                    comparison_count += 1
                    if comparison_count == 1:
                        results.append((0, (f"    [DETAILED ANALYSIS: {name}]", "")))
                    
                    results.append((0, (f"      Comparison {comparison_count}: PID {p1['pid']} ↔ PID {p2['pid']}", "")))
                    
                    for diff_type, diff_value in differences:
                        results.append((0, (f"        {diff_type}: {diff_value}", "")))
                    
                    results.append((0, ("", "")))
        
        return results
    
    def _analyze_single_process(self, target: str, all_processes: List[Dict], parent_names: Dict, expected_parents: Dict) -> None:
        """Analyze a single process"""
        processes = self._find_processes(target, all_processes)
        
        if not processes:
            yield (0, ("ERROR", f"Process '{target}' not found"))
            return
        
        yield (0, ("[PROCESS ANALYSIS]", ""))
        yield (0, (f"Target: {target}", ""))
        yield (0, (f"Instances found: {len(processes)}", ""))
        yield (0, ("", ""))
        
        # Show process details
        yield (0, ("[PROCESS DETAILS]", ""))
        for proc in processes:
            parent_name = parent_names.get(proc['parent_pid'], "Unknown")
            expected_parent = self._get_expected_parent_info(proc['name'], expected_parents)
            parent_info = f"Parent: {parent_name}"
            if expected_parent:
                parent_info += f" | Expected: {expected_parent}"
            
            yield (0, (
                f"  • {proc['name']} (PID: {proc['pid']})", 
                f"{parent_info} | Threads: {proc['thread_count']} | Session: {proc['session_id']}"
            ))
        
        # If multiple instances, compare them
        if len(processes) > 1:
            yield (0, ("", ""))
            yield from self._analyze_process_group(target, processes, parent_names, expected_parents)
        else:
            yield (0, ("", ""))
            yield (0, ("[ANALYSIS]", "Single instance - no comparisons possible"))
    
    def _compare_specific_processes(self, p1_target: str, p2_target: str, all_processes: List[Dict], parent_names: Dict, expected_parents: Dict) -> None:
        """Compare two specific processes"""
        p1_processes = self._find_processes(p1_target, all_processes)
        p2_processes = self._find_processes(p2_target, all_processes)
        
        if not p1_processes:
            yield (0, ("ERROR", f"Process '{p1_target}' not found"))
            return
            
        if not p2_processes:
            yield (0, ("ERROR", f"Process '{p2_target}' not found"))
            return
        
        yield (0, ("[PROCESS COMPARISON ANALYSIS]", ""))
        yield (0, (f"Target: {p1_target} vs {p2_target}", ""))
        yield (0, (f"Processes found: {len(p1_processes)} {p1_target}, {len(p2_processes)} {p2_target}", ""))
        yield (0, ("", ""))
        
        # Process details section
        yield (0, ("[PROCESS DETAILS]", ""))
        
        seen_pids = set()
        all_target_processes = []
        
        for proc in p1_processes + p2_processes:
            if proc['pid'] not in seen_pids:
                seen_pids.add(proc['pid'])
                all_target_processes.append(proc)
        
        for proc in all_target_processes:
            parent_name = parent_names.get(proc['parent_pid'], "Unknown")
            expected_parent = self._get_expected_parent_info(proc['name'], expected_parents)
            parent_info = f"Parent: {parent_name}"
            if expected_parent:
                parent_info += f" | Expected: {expected_parent}"
            
            yield (0, (
                f"  • {proc['name']} (PID: {proc['pid']})", 
                f"{parent_info} | Threads: {proc['thread_count']} | Session: {proc['session_id']}"
            ))
        
        yield (0, ("", ""))
        
        # Comparison section
        comparison_count = 0
        seen_comparisons = set()
        
        for p1 in p1_processes:
            for p2 in p2_processes:
                if p1['pid'] == p2['pid']:
                    continue
                
                comp_key = tuple(sorted([p1['pid'], p2['pid']]))
                if comp_key in seen_comparisons:
                    continue
                seen_comparisons.add(comp_key)
                
                comparison_count += 1
                differences = self._compare_processes(p1, p2, parent_names, expected_parents)
                
                if differences:
                    yield (0, (f"[COMPARISON {comparison_count}]", ""))
                    yield (0, (f"  {p1['name']} [{p1['pid']}]  ↔  {p2['name']} [{p2['pid']}]", ""))
                    yield (0, ("", ""))
                    
                    for diff_type, diff_value in differences:
                        yield (0, (f"    {diff_type}:", diff_value))
                    
                    yield (0, ("", ""))
        
        # Summary
        yield (0, ("[SUMMARY]", ""))
        yield (0, (f"Comparisons performed: {comparison_count}", ""))
    
    def _get_all_processes(self) -> List[Dict[str, Any]]:
        """Get all processes from memory"""
        processes = []
        for proc in pslist.PsList.list_processes(self.context, self.config["kernel"]):
            try:
                process_data = self._extract_process_data(proc)
                if process_data:
                    processes.append(process_data)
            except:
                continue
        return processes
    
    def _build_parent_name_map(self, processes: List[Dict]) -> Dict[int, str]:
        """Build mapping of PID to process names"""
        parent_map = {}
        for process in processes:
            parent_map[process['pid']] = process['name']
        parent_map[0] = "System"
        parent_map[4] = "System"
        return parent_map
    
    def _build_expected_parents_map(self) -> Dict[str, str]:
        """Build mapping of expected parent relationships"""
        return {
            'smss.exe': 'System',
            'csrss.exe': 'smss.exe',
            'wininit.exe': 'smss.exe',
            'services.exe': 'wininit.exe',
            'lsass.exe': 'wininit.exe',
            'winlogon.exe': 'smss.exe',
            'svchost.exe': 'services.exe',
            'spoolsv.exe': 'services.exe',
            'taskhost.exe': 'services.exe',
            'dwm.exe': 'services.exe',
            'explorer.exe': 'userinit.exe',
            'userinit.exe': 'winlogon.exe',
            'runtimebroker.exe': 'svchost.exe',
            'searchui.exe': 'svchost.exe',
            'sihost.exe': 'services.exe',
            'ctfmon.exe': 'services.exe',
            'lsm.exe': 'services.exe',
            'taskeng.exe': 'services.exe',
            'audiodg.exe': 'services.exe',
            'conhost.exe': 'csrss.exe',
            'msmpeng.exe': 'services.exe',
            'securityhealthservice.exe': 'services.exe'
        }
    
    def _get_expected_parent_info(self, process_name: str, expected_parents: Dict) -> str:
        """Get expected parent information for a process"""
        expected = expected_parents.get(process_name.lower())
        if expected:
            return f"{expected} (Expected)"
        return ""
    
    def _extract_process_data(self, proc) -> Dict[str, Any]:
        """Extract process data"""
        try:
            pid = int(proc.UniqueProcessId)
            name = self._get_process_name(proc)
            parent_pid = self._get_parent_pid(proc)
            session_id = self._get_session_id(proc)
            thread_count = self._get_thread_count(proc)
            
            return {
                'pid': pid,
                'name': name,
                'parent_pid': parent_pid,
                'session_id': session_id,
                'thread_count': thread_count,
                'process': proc
            }
        except:
            return None
    
    def _find_processes(self, target: str, processes: List[Dict]) -> List[Dict]:
        """Find processes by name or PID"""
        matches = []
        if target.isdigit():
            pid_target = int(target)
            for process in processes:
                if process['pid'] == pid_target:
                    matches.append(process)
        else:
            name_target = target.lower()
            for process in processes:
                if process['name'].lower() == name_target:
                    matches.append(process)
        return matches
    
    def _compare_processes(self, p1: Dict, p2: Dict, parent_names: Dict, expected_parents: Dict) -> List[Tuple]:
        """Compare two processes"""
        differences = []
        
        # Get parent names
        p1_parent_name = parent_names.get(p1['parent_pid'], "Unknown")
        p2_parent_name = parent_names.get(p2['parent_pid'], "Unknown")
        
        # Parent comparison with expected parent info
        if p1['parent_pid'] != p2['parent_pid']:
            p1_expected = self._get_expected_parent_info(p1['name'], expected_parents)
            p2_expected = self._get_expected_parent_info(p2['name'], expected_parents)
            
            parent_info = f"{p1_parent_name} ({p1['parent_pid']})"
            if p1_expected:
                parent_info += f" [{p1_expected}]"
            
            parent_info += f"  →  {p2_parent_name} ({p2['parent_pid']})"
            if p2_expected:
                parent_info += f" [{p2_expected}]"
            
            differences.append(("Parent Process", parent_info))
        
        # Thread count comparison
        if p1['thread_count'] != p2['thread_count']:
            thread_diff = p1['thread_count'] - p2['thread_count']
            diff_type = "more" if thread_diff > 0 else "fewer"
            differences.append((
                "Thread Count", 
                f"{p1['thread_count']}  →  {p2['thread_count']} ({abs(thread_diff)} {diff_type})"
            ))
        
        # Session comparison
        if p1['session_id'] != p2['session_id']:
            differences.append((
                "Session ID",
                f"{p1['session_id']}  →  {p2['session_id']}"
            ))
        
        return differences
    
    def _get_process_name(self, proc) -> str:
        """Get process name"""
        try:
            return utility.array_to_string(proc.ImageFileName)
        except:
            return "Unknown"
    
    def _get_parent_pid(self, proc) -> int:
        """Get parent PID"""
        try:
            if hasattr(proc, 'InheritedFromUniqueProcessId'):
                return int(proc.InheritedFromUniqueProcessId)
        except:
            pass
        return 0
    
    def _get_session_id(self, proc) -> int:
        """Get session ID"""
        try:
            if hasattr(proc, 'SessionId'):
                return int(proc.SessionId)
        except:
            pass
        return -1
    
    def _get_thread_count(self, proc) -> int:
        """Get thread count"""
        try:
            if hasattr(proc, 'ActiveThreads'):
                return int(proc.ActiveThreads)
        except:
            pass
        return 0
    
    def run(self):
        columns = [
            ("Analysis", str),
            ("Details", str)
        ]
        return renderers.TreeGrid(columns, self._generator())
