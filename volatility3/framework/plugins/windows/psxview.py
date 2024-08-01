import datetime, logging, string

from volatility3.framework import constants, exceptions
from volatility3.framework.interfaces import plugins
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints, TreeGrid
from volatility3.plugins.windows import (
    handles,
    info,
    pslist,
    psscan,
    sessions,
    thrdscan,
)

vollog = logging.getLogger(__name__)


class PsXView(plugins.PluginInterface):
    """Lists all processes found via four of the methods described in \"The Art of Memory Forensics,\" which may help
    identify processes that are trying to hide themselves. I recommend using -r pretty if you are looking at this
    plugin's output in a terminal."""

    # I've omitted the desktop thread scanning method because Volatility3 doesn't appear to have the funcitonality
    # which the original plugin used to do it.

    # The sessions method is omitted because it begins with the list of processes found by Pslist anyway.

    # Lastly, I've omitted the pspcid method because I could not for the life of me get it to work. I saved the
    # code I do have from it, and will happily share it if anyone else wants to add it.

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    valid_proc_name_chars = set(
        string.ascii_lowercase + string.ascii_uppercase + "." + " "
    )

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="info", component=info.Info, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="psscan", component=psscan.PsScan, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="thrdscan", component=thrdscan.ThrdScan, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="handles", component=handles.Handles, version=(1, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="physical-offsets",
                description="List processes with physical offsets instead of virtual offsets.",
                optional=True,
            ),
        ]

    def _proc_name_to_string(self, proc):
        return proc.ImageFileName.cast(
            "string", max_length=proc.ImageFileName.vol.count, errors="replace"
        )

    def _is_valid_proc_name(self, str):
        for c in str:
            if not c in self.valid_proc_name_chars:
                return False
        return True

    def _filter_garbage_procs(self, proc_list):
        return [
            p
            for p in proc_list
            if p.is_valid() and self._is_valid_proc_name(self._proc_name_to_string(p))
        ]

    def _translate_offset(self, offset):
        if not self.config["physical-offsets"]:
            return offset

        kernel = self.context.modules[self.config["kernel"]]
        layer_name = kernel.layer_name

        try:
            _, _, offset, _, _ = list(
                self.context.layers[layer_name].mapping(offset=offset, length=0)
            )[0]
        except exceptions.PagedInvalidAddressException:
            vollog.debug(f"Page fault: unable to translate {offset:0x}")

        return offset

    def _proc_list_to_dict(self, tasks):
        tasks = self._filter_garbage_procs(tasks)
        return {self._translate_offset(proc.vol.offset): proc for proc in tasks}

    def _check_pslist(self, tasks):
        return self._proc_list_to_dict(tasks)

    def _check_psscan(self, layer_name, symbol_table):
        res = psscan.PsScan.scan_processes(
            context=self.context, layer_name=layer_name, symbol_table=symbol_table
        )

        return self._proc_list_to_dict(res)

    def _check_thrdscan(self):
        ret = []

        for ethread in thrdscan.ThrdScan.scan_threads(
            self.context, module_name="kernel"
        ):
            process = None
            try:
                process = ethread.owning_process()
                if not process.is_valid():
                    continue

                ret.append(process)
            except AttributeError:
                vollog.log(
                    constants.LOGLEVEL_VVV,
                    "Unable to find the owning process of ethread",
                )

        return self._proc_list_to_dict(ret)

    def _check_csrss_handles(self, tasks, layer_name, symbol_table):
        ret = []

        for p in tasks:
            name = self._proc_name_to_string(p)
            if name == "csrss.exe":
                try:
                    if p.has_member("ObjectTable"):
                        handles_plugin = handles.Handles(
                            context=self.context, config_path=self.config_path
                        )
                        hndls = list(handles_plugin.handles(p.ObjectTable))
                        for h in hndls:
                            if (
                                h.get_object_type(
                                    handles_plugin.get_type_map(
                                        self.context, layer_name, symbol_table
                                    )
                                )
                                == "Process"
                            ):
                                ret.append(h.Body.cast("_EPROCESS"))

                except exceptions.InvalidAddressException:
                    vollog.log(
                        constants.LOGLEVEL_VVV, "Cannot access eprocess object table"
                    )

        return self._proc_list_to_dict(ret)

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        layer_name = kernel.layer_name
        symbol_table = kernel.symbol_table_name

        kdbg_list_processes = list(
            pslist.PsList.list_processes(
                context=self.context, layer_name=layer_name, symbol_table=symbol_table
            )
        )

        # get processes from each source
        processes = {}

        processes["pslist"] = self._check_pslist(kdbg_list_processes)
        processes["psscan"] = self._check_psscan(layer_name, symbol_table)
        processes["thrdscan"] = self._check_thrdscan()
        processes["csrss"] = self._check_csrss_handles(
            kdbg_list_processes, layer_name, symbol_table
        )

        # print results

        # list of lists of offsets
        todo_offsets = [list(processes[source].keys()) for source in processes]

        # flatten to one list
        todo_offsets = sum(todo_offsets, [])

        # remove duplicates
        todo_offsets = set(todo_offsets)

        for offset in todo_offsets:
            proc = None

            in_sources = {src: False for src in processes}

            for source in processes:
                if offset in processes[source]:
                    in_sources[source] = True
                    if not proc:
                        proc = processes[source][offset]

            pid = proc.UniqueProcessId
            name = self._proc_name_to_string(proc)

            exit_time = proc.get_exit_time()
            if type(exit_time) != datetime.datetime:
                exit_time = ""
            else:
                exit_time = str(exit_time)

            yield (
                0,
                (
                    format_hints.Hex(offset),
                    name,
                    pid,
                    in_sources["pslist"],
                    in_sources["psscan"],
                    in_sources["thrdscan"],
                    in_sources["csrss"],
                    exit_time,
                ),
            )

    def run(self):
        offset_type = "(Physical)" if self.config["physical-offsets"] else "(Virtual)"
        offset_str = "Offset" + offset_type

        return TreeGrid(
            [
                (offset_str, format_hints.Hex),
                ("Name", str),
                ("PID", int),
                ("pslist", bool),
                ("psscan", bool),
                ("thrdscan", bool),
                ("csrss", bool),
                ("Exit Time", str),
            ],
            self._generator(),
        )
