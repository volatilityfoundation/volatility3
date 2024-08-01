import datetime
from typing import List, Iterable, Set, Dict
from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.plugins.windows import pslist, psscan

class PsXview(plugins.PluginInterface):
    """Find hidden processes with various process listings"""
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name='primary',
                            description='Memory layer for the kernel',
                            architectures=["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name="nt_symbols",
                            description="Windows kernel symbols"),
        ]

    @classmethod
    def check_pslist(cls, context: interfaces.context.ContextInterface, layer_name: str, symbol_table: str) -> Set[int]:
        """Enumerate processes from PsActiveProcessHead"""
        return {proc.UniqueProcessId for proc in pslist.PsList.list_processes(context, layer_name, symbol_table)}

    @classmethod
    def check_psscan(cls, context: interfaces.context.ContextInterface, layer_name: str, symbol_table: str) -> Iterable[interfaces.objects.ObjectInterface]:
        """Enumerate processes with pool tag scanning"""
        return psscan.PsScan.scan_processes(context, layer_name, symbol_table)

    @classmethod
    def check_thrdproc(cls, context: interfaces.context.ContextInterface, layer_name: str, symbol_table: str) -> Dict[int, bool]:
        """Enumerate processes indirectly by ETHREAD scanning"""
        thrdproc_info = {}
        processes = pslist.PsList.list_processes(context, layer_name, symbol_table)
        for proc in processes:
            try:
                threads = cls.list_threads(proc)
                thrdproc_info[proc.UniqueProcessId] = len(threads) > 0
            except AttributeError:
                continue
        return thrdproc_info

    @classmethod
    def list_threads(cls, proc):
        """Lists the threads of a process"""
        threads = []
        try:
            thread_list_entry = proc.ThreadListHead.Flink
            while thread_list_entry != 0 and thread_list_entry != proc.ThreadListHead.vol.offset:
                thread = thread_list_entry.dereference().cast("_ETHREAD")
                threads.append(thread)
                thread_list_entry = thread.ThreadListEntry.Flink
        except:
            pass
        return threads

    def _generator(self, psscan_tasks, pslist_pids, thrdproc_info):
        pslist_tasks = pslist.PsList.list_processes(self.context, self.config['primary'], self.config['nt_symbols'])
        pslist_task_map = {proc.UniqueProcessId: proc for proc in pslist_tasks}

        for task in psscan_tasks:
            pid = int(task.UniqueProcessId)
            pslist_present = pid in pslist_pids
            pslist_task = pslist_task_map.get(pid)
            session_id = pslist_task.get_session_id() if pslist_task else None

            if session_id == 0:
                session_id_str = "True"
            elif session_id == 1:
                session_id_str = "False"
            else:
                session_id_str = "-"

            thrdproc_present = thrdproc_info.get(pid, False)

            name_str = str(task.ImageFileName.cast("string", max_length=task.ImageFileName.vol.count)).strip()
            name_str = name_str[:20].ljust(20)

            yield (
                0,
                [
                    f"0x{task.vol.offset:08x}",
                    name_str,
                    f"{pid:>5}",
                    pslist_present,
                    True,
                    session_id_str,
                    thrdproc_present,
                    task.get_exit_time() if task.get_exit_time() else None
                ]
            )

        for task in pslist_tasks:
            pid = int(task.UniqueProcessId)
            psscan_present = pid in {int(proc.UniqueProcessId) for proc in psscan_tasks}
            session_id = task.get_session_id()

            if session_id == 0:
                session_id_str = "True"
            elif session_id == 1:
                session_id_str = "False"
            else:
                session_id_str = "-"

            if not psscan_present:
                thrdproc_present = thrdproc_info.get(pid, False)

                name_str = str(task.ImageFileName.cast("string", max_length=task.ImageFileName.vol.count)).strip()
                name_str = name_str[:20].ljust(20)

                yield (
                    0,
                    [
                        f"0x{task.vol.offset:08x}",
                        name_str,
                        f"{pid:>5}",
                        True,
                        False,
                        session_id_str,
                        thrdproc_present,
                        task.get_exit_time() if task.get_exit_time() else None
                    ]
                )

    def run(self):
        pslist_pids = self.check_pslist(
            self.context,
            self.config['primary'],
            self.config['nt_symbols']
        )

        psscan_tasks = self.check_psscan(
            self.context,
            self.config['primary'],
            self.config['nt_symbols']
        )

        thrdproc_info = self.check_thrdproc(
            self.context,
            self.config['primary'],
            self.config['nt_symbols']
        )

        return renderers.TreeGrid(
            [
                ("Offset(P)", str), 
                ("Name                ", str), 
                ("  PID", str), 
                ("pslist", bool), 
                ("psscan", bool), 
                ("session", str), 
                ("thrdproc", bool), 
                ("ExitTime", datetime.datetime)
            ],
            self._generator(psscan_tasks, pslist_pids, thrdproc_info)
        )
