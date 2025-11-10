import logging
from typing import List
from collections import defaultdict
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)

class DuplicateProcs(interfaces.plugins.PluginInterface):
    """Lists processes running multiple instances."""
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
            requirements.IntRequirement(
                name="min_count",
                description="Minimum number of instances to display (default: 2)",
                optional=True,
                default=2
            ),
            requirements.IntRequirement(
                name="pid",
                description="Filter by specific process ID",
                optional=True,
                default=None
            ),
        ]
    
    def _generator(self):
        kernel_module_name = self.config["kernel"]
        min_count = self.config.get("min_count", 2)
        target_pid = self.config.get("pid")
        
        process_instances = defaultdict(list)
        
        # Collect all processes
        for proc in pslist.PsList.list_processes(self.context, kernel_module_name):
            try:
                proc_name = proc.ImageFileName.cast(
                    "string",
                    max_length=proc.ImageFileName.vol.count,
                    errors="replace"
                )
                
                proc_pid = proc.UniqueProcessId
                proc_ppid = proc.InheritedFromUniqueProcessId
                
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
                
                process_instances[proc_name].append({
                    "PID": proc_pid,
                    "PPID": proc_ppid,
                    "Path": proc_path
                })
                
            except Exception as e:
                vollog.debug(f"Error processing process: {e}")
                continue
        
        # Output processes with multiple instances
        for proc_name, instances in sorted(process_instances.items()):
            count = len(instances)
            
            # If target_pid is specified, filter by that PID
            if target_pid is not None:
                matching_instances = [inst for inst in instances if inst["PID"] == target_pid]
                if matching_instances and count >= min_count:
                    for instance in instances:
                        yield (0, (
                            proc_name,
                            instance["PID"],
                            instance["PPID"],
                            instance["Path"]
                        ))
            else:
                # Normal behavior: show all processes with multiple instances
                if count >= min_count:
                    for instance in instances:
                        yield (0, (
                            proc_name,
                            instance["PID"],
                            instance["PPID"],
                            instance["Path"]
                        ))
    
    def run(self):
        return renderers.TreeGrid(
            [
                ("Process Name", str),
                ("PID", int),
                ("PPID", int),
                ("File Path", str)
            ],
            self._generator(),
        )