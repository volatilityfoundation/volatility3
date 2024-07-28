import datetime, logging

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
    """Lists all processes found via 6 of the methods described in \"The Art of Memory Forensics,\" which may help
    identify processes that are trying to hide themselves. I recommend using -r pretty if you are looking at this
    plugin's output in a terminal."""

    # I've omitted the desktop thread scanning method because Volatility3 doesn't appear to have the funcitonality
    # which the original plugin to do it.

    # I don't think it's worth including the sessions method either because both the original psxview plugin
    # and Volatility3's sessions plugin begin with the list of processes found by PsList.
    # The original psxview plugin's session code essentially just filters the pslist for processes
    # whose session ID is not None. I've matched this in my code, but again, it doesn't seem worth including.

    # Lastly, I've omitted the pspcid method because I could not for the life of me get it to work. I saved the
    # code I do have from it, and will happily share it if anyone else wants to add it.

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

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
            requirements.VersionRequirement(
                name="sessions", component=sessions.Sessions, version=(0, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="identify-expected",
                description='In the plugin\'s output, replace false with \
                                                normal where false is the expected result for a Windows machine running normally. \
                                                Keep in mind that this plugin uses simple checks to identify "normal" behavior, \
                                                so you may want to double-check the legitimacy of these processes yourself.',
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="physical-offsets",
                description="List processes with phyiscall offsets instead of virtual offsets.",
                optional=True,
            ),
        ]

    def proc_name_to_string(self, proc):
        return proc.ImageFileName.cast(
            "string", max_length=proc.ImageFileName.vol.count, errors="replace"
        )

    def is_ascii(self, str):
        return str.split(".")[0].isalnum()

    def filter_garbage_procs(self, proc_list):
        return [
            p
            for p in proc_list
            if p.is_valid() and self.is_ascii(self.proc_name_to_string(p))
        ]

    def translate_offset(self, offset):
        if self.config["physical-offsets"]:
            return offset

        kernel = self.context.modules[self.config["kernel"]]
        layer_name = kernel.layer_name

        try:
            offset = list(
                self.context.layers[layer_name].mapping(offset=offset, length=0)
            )[0][2]
        except:
            # already have physical address
            pass

        return offset

    def proc_list_to_dict(self, tasks):
        return {self.translate_offset(proc.vol.offset): proc for proc in tasks}

    def check_pslist(self, tasks):
        res = self.filter_garbage_procs(tasks)
        return self.proc_list_to_dict(tasks)

    def check_psscan(self, layer_name, symbol_table):
        res = psscan.PsScan.scan_processes(
            context=self.context, layer_name=layer_name, symbol_table=symbol_table
        )
        res = self.filter_garbage_procs(res)

        return self.proc_list_to_dict(res)

    def check_thrdscan(self):
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

        return self.proc_list_to_dict(ret)

    def check_csrss_handles(self, tasks, layer_name, symbol_table):
        ret = []

        for p in tasks:
            name = self.proc_name_to_string(p)
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

        ret = self.filter_garbage_procs(ret)
        return self.proc_list_to_dict(ret)

    def check_session(self, pslist_procs):
        procs = [p for p in pslist_procs if p.get_session_id() != None]

        return self.proc_list_to_dict(procs)

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        layer_name = kernel.layer_name
        symbol_table = kernel.symbol_table_name

        kdbg_list_processes = list(
            pslist.PsList.list_processes(
                context=self.context, layer_name=layer_name, symbol_table=symbol_table
            )
        )

        processes = {}

        processes["pslist"] = self.check_pslist(kdbg_list_processes)
        processes["psscan"] = self.check_psscan(layer_name, symbol_table)
        processes["thrdscan"] = self.check_thrdscan()
        processes["csrss"] = self.check_csrss_handles(
            kdbg_list_processes, layer_name, symbol_table
        )
        processes["sessions"] = self.check_session(kdbg_list_processes)

        seen_offsets = set()
        for source in processes:
            for offset in processes[source]:
                if offset not in seen_offsets:
                    seen_offsets.add(offset)
                    proc = processes[source][offset]

                    pid = proc.UniqueProcessId
                    name = self.proc_name_to_string(proc)

                    exit_time = proc.get_exit_time()
                    if type(exit_time) != datetime.datetime:
                        exit_time = ""
                    else:
                        exit_time = str(exit_time)

                    in_sources = {
                        src: str(offset in processes[src]) for src in processes
                    }

                    if self.config["identify-expected"]:
                        f = "False"
                        n = "Normal"

                        if in_sources["pslist"] == f:
                            if exit_time != "":
                                in_sources["pslist"] = n

                        if in_sources["thrdscan"] == f:
                            if exit_time != "":
                                in_sources["thrdscan"] = n

                        if in_sources["csrss"] == f:
                            if name.lower() in ["system", "smss.exe", "csrss.exe"]:
                                in_sources["csrss"] = n
                            elif exit_time != "":
                                in_sources["csrss"] = n

                        if in_sources["sessions"] == f:
                            if name.lower() in ["system", "smss.exe"]:
                                in_sources["sessions"] = n

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
                            in_sources["sessions"],
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
                ("pslist", str),
                ("psscan", str),
                ("thrdscan", str),
                ("csrss", str),
                ("sessions", str),
                ("Exit Time", str),
            ],
            self._generator(),
        )
