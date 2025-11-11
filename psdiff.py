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
            )
        ]
    
    def _generator(self):
        p1_target = self.config.get("p1")
        p2_target = self.config.get("p2")
        
        try:
            # Get all processes
            all_processes = self._get_all_processes()
            parent_names = self._build_parent_name_map(all_processes)
            
            if not p1_target and not p2_target:
                # Analyze all processes for anomalies
                yield from self._analyze_all_processes(all_processes, parent_names)
            elif p1_target and not p2_target:
                # Analyze single process
                yield from self._analyze_single_process(p1_target, all_processes, parent_names)
            elif p1_target and p2_target:
                # Compare two specific processes
                yield from self._compare_specific_processes(p1_target, p2_target, all_processes, parent_names)
            else:
                yield (0, ("ERROR", "Invalid parameters: -p2 requires -p1"))
            
        except Exception as e:
            yield (0, ("ERROR", f"Analysis failed: {str(e)}"))
    
    def _analyze_all_processes(self, all_processes: List[Dict], parent_names: Dict) -> None:
        """Analyze all processes for anomalies"""
        yield (0, ("[PROCESS ANOMALY ANALYSIS]", ""))
        yield (0, ("Scanning all processes for suspicious patterns", ""))
        yield (0, (f"Total processes found: {len(all_processes)}", ""))
        yield (0, ("", ""))
        
        # Group processes by name
        process_groups = {}
        for proc in all_processes:
            name = proc['name']
            if name not in process_groups:
                process_groups[name] = []
            process_groups[name].append(proc)
        
        # Find processes with multiple instances and differences
        suspicious_count = 0
        
        for name, instances in process_groups.items():
            if len(instances) > 1:
                # Check for differences between instances
                differences_found = self._analyze_process_group(name, instances, parent_names)
                if differences_found:
                    suspicious_count += 1
                    yield from differences_found
        
        yield (0, ("", ""))
        yield (0, ("[SUMMARY]", ""))
        if suspicious_count == 0:
            yield (0, ("No suspicious process patterns detected", ""))
        else:
            yield (0, (f"Found {suspicious_count} processes with suspicious patterns", ""))
    
    def _analyze_process_group(self, name: str, instances: List[Dict], parent_names: Dict) -> List[Tuple]:
        """Analyze a group of processes with the same name"""
        results = []
        comparison_count = 0
        
        # Compare each unique pair
        for i in range(len(instances)):
            for j in range(i + 1, len(instances)):
                p1 = instances[i]
                p2 = instances[j]
                
                differences = self._compare_processes(p1, p2, parent_names)
                if differences:
                    comparison_count += 1
                    if comparison_count == 1:
                        results.append((0, (f"[PROCESS GROUP: {name}]", "")))
                        results.append((0, (f"Multiple instances found: {len(instances)}", "")))
                        results.append((0, ("", "")))
                    
                    results.append((0, (f"  Comparison {comparison_count}", "")))
                    results.append((0, (f"    {p1['name']} [{p1['pid']}]  ↔  {p2['name']} [{p2['pid']}]", "")))
                    results.append((0, ("", "")))
                    
                    for diff_type, diff_value in differences:
                        results.append((0, (f"      {diff_type}:", diff_value)))
                    
                    results.append((0, ("", "")))
        
        return results
    
    def _analyze_single_process(self, target: str, all_processes: List[Dict], parent_names: Dict) -> None:
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
            yield (0, (
                f"  • {proc['name']} (PID: {proc['pid']})", 
                f"Parent: {parent_name} | Threads: {proc['thread_count']} | Session: {proc['session_id']}"
            ))
        
        # If multiple instances, compare them
        if len(processes) > 1:
            yield (0, ("", ""))
            yield from self._analyze_process_group(target, processes, parent_names)
        else:
            yield (0, ("", ""))
            yield (0, ("[ANALYSIS]", "Single instance - no comparisons possible"))
    
    def _compare_specific_processes(self, p1_target: str, p2_target: str, all_processes: List[Dict], parent_names: Dict) -> None:
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
            yield (0, (
                f"  • {proc['name']} (PID: {proc['pid']})", 
                f"Parent: {parent_name} | Threads: {proc['thread_count']} | Session: {proc['session_id']}"
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
                differences = self._compare_processes(p1, p2, parent_names)
                
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
    
    def _compare_processes(self, p1: Dict, p2: Dict, parent_names: Dict) -> List[Tuple]:
        """Compare two processes"""
        differences = []
        
        # Get parent names
        p1_parent_name = parent_names.get(p1['parent_pid'], "Unknown")
        p2_parent_name = parent_names.get(p2['parent_pid'], "Unknown")
        
        # Parent comparison
        if p1['parent_pid'] != p2['parent_pid']:
            differences.append((
                "Parent Process",
                f"{p1_parent_name} ({p1['parent_pid']})  →  {p2_parent_name} ({p2['parent_pid']})"
            ))
        
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