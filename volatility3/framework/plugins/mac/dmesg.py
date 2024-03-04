# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility

vollog = logging.getLogger(__name__)


class Dmesg(interfaces.plugins.PluginInterface):
    """Prints the kernel log buffer."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Kernel module for the OS",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    @classmethod
    def get_kernel_log_buffer(
        cls, context: interfaces.context.ContextInterface, kernel_module_name: str
    ):
        """
        Online documentation :
            - https://github.com/apple-open-source/macos/blob/master/xnu/bsd/sys/msgbuf.h
            - https://github.com/apple-open-source/macos/blob/ea4cd5a06831aca49e33df829d2976d6de5316ec/xnu/bsd/kern/subr_log.c#L751
        Volatility 2 plugin :
            - https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/mac/dmesg.py
        """

        kernel = context.modules[kernel_module_name]
        if not kernel.has_symbol("msgbufp"):
            raise exceptions.SymbolError(
                'The provided symbol table does not include the "msgbufp" symbol. This means you are either analyzing an unsupported kernel version or that your symbol table is corrupt.'
            )

        msgbufp_ptr = kernel.object_from_symbol(symbol_name="msgbufp")
        msgbufp = msgbufp_ptr.dereference()
        msg_size = msgbufp.msg_size  # max buffer size
        msg_bufx = msgbufp.msg_bufx  # write pointer
        msg_bufc = msgbufp.msg_bufc
        # msg_bufc is circular, meaning that if its size exceeds msg_size,
        # msg_bufx will point to the beginning of the buffer and start overwriting.
        msg_bufc_data: str = utility.pointer_to_string(msg_bufc, msg_size)
        # Avoid OOB reads
        msg_bufx = msg_bufx if msg_bufx <= msg_size else 0
        # We directly take into account the case where the write buffer did a loop,
        # as older messages will start at msg_bufx offset (not overwritten yet).
        dmesg = msg_bufc_data[msg_bufx:]
        dmesg += msg_bufc_data[:msg_bufx]

        # Yield each line
        for dmesg_line in dmesg.splitlines():
            yield (dmesg_line,)

    def _generator(self):
        for value in self.get_kernel_log_buffer(
            context=self.context, kernel_module_name=self.config["kernel"]
        ):
            yield (0, value)

    def run(self):
        return renderers.TreeGrid(
            [
                ("line", str),
            ],
            self._generator(),
        )
