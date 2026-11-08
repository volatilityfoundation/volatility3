import logging
from typing import List
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)

class OrphanProcs(interfaces.plugins.PluginInterface):
    """Finds processes with no parent (possible hidden parent processes)."""
    
    _required_framework_version = (2, 0, 0)
    _version = (1, 1, 0)
    
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel module",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.BooleanRequirement(
                name="include_system",
                description="Include system processes (PID 0, 4) in results",
                optional=True,
                default=False
            ),
        ]
    
    def _generator(self):
        kernel_module_name = self.config["kernel"]
        include_system = self.config.get("include_system", False)
        
        # Collect all PIDs to verify parent existence
        all_pids = set()
        processes = []
        pid_to_name = {}
        
        # First pass: collect all processes
        for proc in pslist.PsList.list_processes(self.context, kernel_module_name):
            try:
                proc_name = proc.ImageFileName.cast(
                    "string",
                    max_length=proc.ImageFileName.vol.count,
                    errors="replace"
                ).strip()
                
                proc_pid = int(proc.UniqueProcessId)
                proc_ppid = int(proc.InheritedFromUniqueProcessId)
                
                # Get process path
                proc_path = "N/A"
                try:
                    peb = proc.get_peb()
                    if peb and peb.ProcessParameters:
                        image_path = peb.ProcessParameters.ImagePathName.get_string()
                        proc_path = image_path if image_path else "N/A"
                except Exception:
                    pass
                
                all_pids.add(proc_pid)
                pid_to_name[proc_pid] = proc_name
                
                processes.append({
                    "Name": proc_name,
                    "PID": proc_pid,
                    "PPID": proc_ppid,
                    "Path": proc_path,
                })
                
            except Exception as e:
                vollog.debug(f"Error processing process {proc.UniqueProcessId}: {e}")
                continue
        
        # Find orphan processes
        orphan_count = 0
        
        for proc_info in processes:
            pid = proc_info["PID"]
            ppid = proc_info["PPID"]
            
            # Skip system processes unless included
            if not include_system and pid in (0, 4):
                continue
            
            # Check if this is an orphan process
            parent_exists = ppid in all_pids
            is_orphan = not parent_exists or (ppid == 0 and pid != 4)
            
            if is_orphan:
                orphan_count += 1
                
                # Simple classification
                if ppid == 0:
                    status = "SYSTEM_CHILD"
                elif not parent_exists:
                    status = "MISSING_PARENT"
                else:
                    status = "ORPHAN"
                
                yield (0, (
                    proc_info["Name"],
                    proc_info["PID"],
                    proc_info["PPID"],
                    status,
                    proc_info["Path"]
                ))
        
        vollog.info(f"Found {orphan_count} orphan processes")
    
    def run(self):
        return renderers.TreeGrid(
            [
                ("Process", str),
                ("PID", int),
                ("PPID", int),
                ("Status", str),
                ("Path", str)
            ],
            self._generator(),
        )