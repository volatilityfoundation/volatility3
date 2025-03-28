# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging

from typing import Optional, Tuple, Generator, Dict

from volatility3.framework import interfaces, exceptions
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, vadinfo

vollog = logging.getLogger(__name__)


class ProcessGhosting(interfaces.plugins.PluginInterface):
    """Lists processes whose DeletePending bit is set or whose FILE_OBJECT is set to 0 or Vads that are DeleteOnClose"""

    _version = (1, 0, 0)
    _required_framework_version = (2, 4, 0)

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="vadinfo", component=vadinfo.VadInfo, version=(2, 0, 1)
            ),
        ]

    @classmethod
    def _process_checks(
        cls,
        proc: interfaces.objects.ObjectInterface,
        mapped_files: Dict[int, Tuple[str, interfaces.objects.ObjectInterface]],
    ) -> Generator[
        Tuple[int, Optional[int], Optional[int], int, Optional[str]], None, None
    ]:
        """
        Checks the EPROCESS for signs of ghosting
        """
        if not proc.has_member("ImageFilePointer"):
            return

        delete_pending = None

        # if it is 0 then its a side effect of process ghosting
        if proc.ImageFilePointer.vol.offset != 0:
            try:
                file_object = proc.ImageFilePointer
                delete_pending = file_object.DeletePending
                file_object = file_object.dereference().vol.offset
            except exceptions.InvalidAddressException:
                file_object = 0

        # ImageFilePointer equal to 0 means process ghosting or similar techniques were used
        else:
            file_object = 0

        # delete_pending besides 0 or 1 = smear
        if isinstance(delete_pending, int) and delete_pending not in [0, 1]:
            vollog.debug(
                f"Invalid delete_pending value {delete_pending} found for process {proc.UniqueProcessId}"
            )
            delete_pending = None

        if file_object == 0 or delete_pending == 1:
            yield file_object, delete_pending, None, proc.SectionBaseAddress

    @classmethod
    def _vad_checks(
        cls, control_area: interfaces.objects.ObjectInterface, vad_path: str
    ) -> Generator[Tuple[int, Optional[int], Optional[int]], None, None]:
        """
        Checks the control area for delete on close or delete pending being set
        """
        try:
            file_object = control_area.FilePointer.dereference().cast("_FILE_OBJECT")
        except exceptions.InvalidAddressException:
            return

        try:
            delete_on_close = control_area.u.Flags.DeleteOnClose
        except exceptions.InvalidAddressException:
            delete_on_close = None

        if delete_on_close and vad_path.lower().endswith((".exe", ".dll")):
            yield file_object.vol.offset, None, delete_on_close

        try:
            delete_pending = file_object.DeletePending
        except exceptions.InvalidAddressException:
            delete_pending = None

        if delete_pending == 1:
            yield file_object.vol.offset, delete_pending, None

    @classmethod
    def check_for_ghosting(
        cls,
        proc: interfaces.objects.ObjectInterface,
        mapped_files: Dict[int, Tuple[str, interfaces.objects.ObjectInterface]],
    ) -> Generator[
        Tuple[int, Optional[int], Optional[int], int, Optional[str]], None, None
    ]:
        """
        Returns process or vad info for ghosting files

        Args:
            proc:
            mapped_files: A dictionary mapping vad base addreses to the path and vad instance for the process

        Return:
            A Generator of tuples of the file object address, the delete pending state, delete on close state, base address of the VAD, and the path
        """
        # check the direct file object of the process
        yield from cls._process_checks(proc, mapped_files)

        # walk each vad, check if it is pending delete or has its delete on close bit set
        for vad_base, (path, vad) in mapped_files.items():
            # these checks have no meaning for private memory areas
            if vad.get_private_memory() == 1:
                continue

            try:
                if vad.has_member("ControlArea"):
                    control_area = vad.ControlArea
                elif vad.has_member("Subsection"):
                    control_area = vad.Subsection.ControlArea
                # We got here from a short vad, likely smear
                else:
                    continue
            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Unable to get control area for vad at base {vad_base:#x} for process with pid {proc.UniqueProcessId}"
                )
                continue

            for file_object_address, delete_pending, delete_on_close in cls._vad_checks(
                control_area, path
            ):
                yield format_hints.Hex(
                    file_object_address
                ), delete_pending, delete_on_close, vad_base

    def _generator(self, procs):
        kernel = self.context.modules[self.config["kernel"]]

        has_imagefilepointer = kernel.get_type("_EPROCESS").has_member(
            "ImageFilePointer"
        )
        if not has_imagefilepointer:
            vollog.warning(
                "ImageFilePointer checks are only supported on Windows 10+ builds when the ImageFilePointer member of _EPROCESS is present"
            )

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)
            pid = proc.UniqueProcessId

            # base address -> (file path, VAD instance)
            mapped_files: Dict[int, Tuple[str, interfaces.objects.ObjectInterface]] = {}
            for vad in vadinfo.VadInfo.list_vads(proc):
                path = vad.get_file_name()
                if isinstance(path, str):
                    mapped_files[vad.get_start()] = (path, vad)

            for (
                file_object_address,
                delete_pending,
                delete_on_close,
                base_address,
            ) in self.check_for_ghosting(proc, mapped_files):
                vad_info = mapped_files.get(base_address)
                if vad_info:
                    path = vad_info[0]
                else:
                    path = renderers.NotAvailableValue()

                yield 0, (
                    pid,
                    process_name,
                    format_hints.Hex(base_address),
                    format_hints.Hex(file_object_address),
                    delete_pending or renderers.NotApplicableValue(),
                    delete_on_close or renderers.NotApplicableValue(),
                    path,
                )

    def run(self):
        filter_func = pslist.PsList.create_active_process_filter()

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Base", format_hints.Hex),
                ("FILE_OBJECT", format_hints.Hex),
                ("DeletePending", int),
                ("DeleteOnClose", int),
                ("Path", str),
            ],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    kernel_module_name=self.config["kernel"],
                    filter_func=filter_func,
                )
            ),
        )
