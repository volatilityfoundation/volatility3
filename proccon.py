import logging
from typing import List, Dict
from collections import defaultdict
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)

class ProcNetViz(interfaces.plugins.PluginInterface):
    """Generates Graphviz DOT file for process tree visualization."""
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
                name="output",
                description="Output file path for DOT file",
                optional=True,
                default="process_tree.dot"
            ),
        ]
    
    def _get_process_data(self, kernel_module_name: str) -> Dict:
        """Extract all process information from memory."""
        processes = {}
        
        for proc in pslist.PsList.list_processes(self.context, kernel_module_name):
            try:
                proc_name = proc.ImageFileName.cast(
                    "string",
                    max_length=proc.ImageFileName.vol.count,
                    errors="replace"
                )
                
                proc_pid = proc.UniqueProcessId
                proc_ppid = proc.InheritedFromUniqueProcessId
                
                # Get full path
                try:
                    peb = proc.get_peb()
                    if peb:
                        process_params = peb.ProcessParameters
                        if process_params:
                            image_path = process_params.ImagePathName.get_string()
                            proc_path = image_path if image_path else proc_name
                        else:
                            proc_path = proc_name
                    else:
                        proc_path = proc_name
                except Exception:
                    proc_path = proc_name
                
                # Get create time
                try:
                    create_time = proc.get_create_time()
                except Exception:
                    create_time = None
                
                # Get threads count
                try:
                    threads = proc.ActiveThreads
                except Exception:
                    threads = 0
                
                processes[proc_pid] = {
                    "name": proc_name,
                    "pid": proc_pid,
                    "ppid": proc_ppid,
                    "path": proc_path,
                    "create_time": create_time,
                    "threads": threads,
                    "children": []
                }
                
            except Exception as e:
                vollog.debug(f"Error processing process: {e}")
                continue
        
        # Build parent-child relationships
        for pid, proc_data in processes.items():
            ppid = proc_data["ppid"]
            if ppid in processes:
                processes[ppid]["children"].append(pid)
        
        return processes
    
    def _generate_dot_content(self, processes: Dict) -> str:
        """Generate Graphviz DOT format content."""
        dot_lines = []
        
        # Header
        dot_lines.append("digraph ProcessTree {")
        dot_lines.append("    rankdir=TB;")
        dot_lines.append("    node [shape=box, style=filled];")
        dot_lines.append("    edge [fontsize=10];")
        dot_lines.append("    ")
        
        # Define node styles
        dot_lines.append("    // Process nodes")
        
        # Find root processes (no parent or parent doesn't exist)
        root_pids = []
        for pid, proc_data in processes.items():
            ppid = proc_data["ppid"]
            if ppid == 0 or ppid not in processes:
                root_pids.append(pid)
        
        # Calculate process depth for better labeling
        def calculate_depth(pid, visited=None):
            if visited is None:
                visited = set()
            if pid in visited:
                return 0
            visited.add(pid)
            ppid = processes[pid]["ppid"]
            if ppid not in processes:
                return 0
            return 1 + calculate_depth(ppid, visited)
        
        # Add process nodes with role labels
        for pid, proc_data in processes.items():
            name = proc_data["name"]
            path = proc_data["path"]
            threads = proc_data["threads"]
            ppid = proc_data["ppid"]
            children = proc_data["children"]
            
            # Determine process role
            depth = calculate_depth(pid)
            if pid in root_pids:
                role = "ROOT"
                fillcolor = "lightcoral"
            elif children:
                if depth == 1:
                    role = "PARENT"
                else:
                    role = f"PARENT (Level {depth})"
                fillcolor = "lightgreen"
            else:
                if depth == 1:
                    role = "CHILD"
                elif depth == 2:
                    role = "SUBCHILD"
                else:
                    role = f"CHILD (Level {depth})"
                fillcolor = "lightblue"
            
            # Escape special characters for DOT format
            safe_name = name.replace('"', '\\"')
            safe_path = path.replace('"', '\\"').replace('\\', '\\\\')
            
            # Build label with role
            label = f"[{role}]\\n{safe_name}\\nPID: {pid} | PPID: {ppid}"
            
            # Add full executable path
            if safe_path != safe_name:
                # Extract just the directory and filename
                if '\\\\' in safe_path:
                    parts = safe_path.split('\\\\')
                    if len(parts) > 3:
                        # Show drive + ... + last 2 directories + file
                        safe_path = parts[0] + '\\\\...\\\\' + '\\\\'.join(parts[-2:])
                label += f"\\nExecuted: {safe_path}"
            
            # Add thread count
            if threads > 0:
                label += f"\\nThreads: {threads}"
            
            # Add child count if parent
            if children:
                label += f"\\nChildren: {len(children)}"
            
            dot_lines.append(
                f'    proc_{pid} [label="{label}", fillcolor="{fillcolor}"];'
            )
        
        dot_lines.append("    ")
        dot_lines.append("    // Parent-child relationships with execution info")
        
        # Add parent-child edges with detailed labels
        edge_count = 0
        for pid, proc_data in processes.items():
            ppid = proc_data["ppid"]
            if ppid in processes:
                parent_name = processes[ppid]["name"]
                child_name = proc_data["name"]
                child_path = proc_data["path"]
                
                # Create descriptive edge label
                edge_label = f"spawned\\n{child_name}"
                
                # Add file path if available and different
                if child_path != child_name and child_path != "N/A":
                    # Get just filename from path
                    if '\\' in child_path:
                        filename = child_path.split('\\')[-1]
                        if filename != child_name:
                            edge_label += f"\\n({filename})"
                
                dot_lines.append(
                    f'    proc_{ppid} -> proc_{pid} [label="{edge_label}", color="darkblue", penwidth=2];'
                )
                edge_count += 1
        
        dot_lines.append("    ")
        dot_lines.append("    // Legend")
        dot_lines.append('    subgraph cluster_legend {')
        dot_lines.append('        label="Legend";')
        dot_lines.append('        style=filled;')
        dot_lines.append('        color=lightgrey;')
        dot_lines.append('        node [shape=box, fontsize=10];')
        dot_lines.append('        legend_root [label="ROOT\\n(No parent)", fillcolor="lightcoral"];')
        dot_lines.append('        legend_parent [label="PARENT\\n(Has children)", fillcolor="lightgreen"];')
        dot_lines.append('        legend_child [label="CHILD/SUBCHILD\\n(Leaf process)", fillcolor="lightblue"];')
        dot_lines.append('        legend_root -> legend_parent [label="spawned", fontsize=9];')
        dot_lines.append('        legend_parent -> legend_child [label="spawned", fontsize=9];')
        dot_lines.append('    }')
        
        # Footer
        dot_lines.append("}")
        
        vollog.info(f"Generated graph with {len(processes)} processes and {edge_count} relationships")
        
        return "\n".join(dot_lines)
    
    def _generator(self):
        kernel_module_name = self.config["kernel"]
        output_file = self.config.get("output", "process_tree.dot")
        
        vollog.info("Extracting process information from memory dump...")
        processes = self._get_process_data(kernel_module_name)
        
        vollog.info(f"Found {len(processes)} processes")
        vollog.info("Generating DOT file...")
        dot_content = self._generate_dot_content(processes)
        
        # Write to file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(dot_content)
            vollog.info(f"DOT file written to: {output_file}")
            
            # Count root processes and total relationships
            root_count = sum(1 for p in processes.values() if p["ppid"] == 0 or p["ppid"] not in processes)
            relationship_count = sum(1 for p in processes.values() if p["ppid"] in processes)
            
            yield (0, (
                output_file,
                len(processes),
                root_count,
                relationship_count,
                "Success"
            ))
            
        except Exception as e:
            vollog.error(f"Failed to write DOT file: {e}")
            yield (0, (
                output_file,
                len(processes),
                0,
                0,
                f"Error: {str(e)}"
            ))
    
    def run(self):
        return renderers.TreeGrid(
            [
                ("Output File", str),
                ("Total Processes", int),
                ("Root Processes", int),
                ("Relationships", int),
                ("Status", str)
            ],
            self._generator(),
        )