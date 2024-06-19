# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging

from volatility3.framework import interfaces, exceptions
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class ProcessGhosting(interfaces.plugins.PluginInterface):
    """Lists processes whose DeletePending bit is set or whose FILE_OBJECT is set to 0"""

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
                name="pslist", component=pslist.PsList, version=(2, 0, 0)
            ),
        ]

    def _generator(self, procs):
        kernel = self.context.modules[self.config["kernel"]]

        if not kernel.get_type("_EPROCESS").has_member("ImageFilePointer"):
            vollog.warning(
                "This plugin only supports Windows 10 builds when the ImageFilePointer member of _EPROCESS is present"
            )
            return

        for proc in procs:
            delete_pending = renderers.UnreadableValue()
            process_name = utility.array_to_string(proc.ImageFileName)

            # if it is 0 then its a side effect of process ghosting
            if proc.ImageFilePointer.vol.offset != 0:
                try:
                    file_object = proc.ImageFilePointer
                    delete_pending = file_object.DeletePending
                except exceptions.InvalidAddressException:
                    file_object = 0

            # ImageFilePointer equal to 0 means process ghosting or similar techniques were used
            else:
                file_object = 0

            # delete_pending besides 0 or 1 = smear
            if file_object == 0 or delete_pending == 1:
                path = renderers.UnreadableValue()
                if file_object:
                    try:
                        path = file_object.FileName.String
                    except exceptions.InvalidAddressException:
                        path = renderers.UnreadableValue()

                yield (
                    0,
                    (
                        proc.UniqueProcessId,
                        process_name,
                        format_hints.Hex(file_object),
                        delete_pending,
                        path,
                    ),
                )

    def run(self):
        filter_func = pslist.PsList.create_active_process_filter()
        kernel = self.context.modules[self.config["kernel"]]

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("FILE_OBJECT", format_hints.Hex),
                ("DeletePending", str),
                ("Path", str),
            ],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    layer_name=kernel.layer_name,
                    symbol_table=kernel.symbol_table_name,
                    filter_func=filter_func,
                )
            ),
        )
