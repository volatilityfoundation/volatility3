# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import re
import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import Generator, Iterator, List, Tuple

from volatility3.framework import (
    class_subclasses,
    constants,
    interfaces,
    renderers,
)
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility

vollog = logging.getLogger(__name__)


class DescStateEnum(Enum):
    desc_miss = -1  # ID mismatch (pseudo state)
    desc_reserved = 0x0  # reserved, in use by writer
    desc_committed = 0x1  # committed by writer, could get reopened
    desc_finalized = 0x2  # committed, no further modification allowed
    desc_reusable = 0x3  # free, not yet used by any writer


class ABCKmsg(ABC):
    """Kernel log buffer reader"""

    LEVELS = (
        "emerg",  # system is unusable
        "alert",  # action must be taken immediately
        "crit",  # critical conditions
        "err",  # error conditions
        "warn",  # warning conditions
        "notice",  # normal but significant condition
        "info",  # informational
        "debug",  # debug-level messages
    )

    FACILITIES = (
        "kern",  # kernel messages
        "user",  # random user-level messages
        "mail",  # mail system
        "daemon",  # system daemons
        "auth",  # security/authorization messages
        "syslog",  # messages generated internally by syslogd
        "lpr",  # line printer subsystem
        "news",  # network news subsystem
        "uucp",  # UUCP subsystem
        "cron",  # clock daemon
        "authpriv",  # security/authorization messages (private)
        "ftp",  # FTP daemon
    )

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config: interfaces.configuration.HierarchicalDict,
    ):
        self._context = context
        self._config = config
        self.vmlinux = context.modules[self._config["kernel"]]
        self.layer_name = self.vmlinux.layer_name  # type: ignore
        self.long_unsigned_int_size = self.vmlinux.get_type("long unsigned int").size

    @classmethod
    def run_all(
        cls,
        context: interfaces.context.ContextInterface,
        config: interfaces.configuration.HierarchicalDict,
    ) -> Iterator[Tuple[str, str, str, str, str]]:
        """It calls each subclass symtab_checks() to test the required
        conditions to that specific kernel implementation.

        Args:
            context: The volatility3 context on which to operate
            config: Core configuration

        Yields:
            kmsg records
        """
        vmlinux = context.modules[config["kernel"]]

        kmsg_inst = None  # type: ignore
        for subclass in class_subclasses(cls):
            if not subclass.symtab_checks(vmlinux=vmlinux):
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    "Kmsg implementation '%s' doesn't match this memory dump",
                    subclass.__name__,
                )
                continue

            vollog.log(
                constants.LOGLEVEL_VVVV,
                "Kmsg implementation '%s' matches!",
                subclass.__name__,
            )
            kmsg_inst = subclass(context=context, config=config)
            yield from kmsg_inst.run()
            # So far, it allows only one implementation to be executed for each
            # specific kernel.
            break

        if kmsg_inst is None:
            vollog.error("Unsupported kernel ring buffer implementation")

    @abstractmethod
    def run(self) -> Iterator[Tuple[str, str, str, str, str]]:
        """Walks through the specific kernel implementation."""

    @classmethod
    @abstractmethod
    def symtab_checks(cls, vmlinux: interfaces.context.ModuleInterface) -> bool:
        """This method on each sublasss will be called to evaluate if the kernel
        being analyzed fulfill the type & symbols requirements for the implementation.
        The first class returning True will be instantiated and called via the
        run() method.

        :return: True is the kernel being analysed fulfill the class requirements.
        """

    def get_string(self, addr: int, length: int) -> str:
        txt = self._context.layers[self.layer_name].read(addr, length)  # type: ignore
        return txt.decode(encoding="utf8", errors="replace")

    def nsec_to_sec_str(self, nsec: int) -> str:
        # See kernel/printk/printk.c:print_time()
        #   Here, we could simply do:
        #       "%.6f" % (nsec / 1000000000.0)
        #   However, that will cause a roundoff error. For instance, using
        #   17110365556 as input, the above will result in 17.110366.
        #   While the kernel print_time function will result in 17.110365.
        #   This might seem insignificant but it could cause some issues
        #   when compared with userland tool results or when used in
        #   timelines.
        return "%lu.%06lu" % (nsec / 1000000000, (nsec % 1000000000) / 1000)

    def get_timestamp_in_sec_str(self, obj) -> str:
        # obj could be log, printk_log or printk_info
        return self.nsec_to_sec_str(obj.ts_nsec)

    def get_caller(self, obj):
        # In some kernel versions, it's only available if CONFIG_PRINTK_CALLER is defined.
        # caller_id is a member of printk_log struct from 5.1 to the latest 5.9
        # From kernels 5.10 on, it's a member of printk_info struct
        if obj.has_member("caller_id"):
            return self.get_caller_text(obj.caller_id)
        else:
            return renderers.NotAvailableValue()

    def get_caller_text(self, caller_id):
        caller_name = "CPU" if caller_id & 0x80000000 else "Task"
        caller = "%s(%u)" % (caller_name, caller_id & ~0x80000000)
        return caller

    def get_prefix(self, obj) -> Tuple[int, int, str, str]:
        # obj could be log, printk_log or printk_info
        return (
            obj.facility,
            obj.level,
            self.get_timestamp_in_sec_str(obj),
            self.get_caller(obj),
        )

    @classmethod
    def get_level_text(cls, level: int) -> str:
        if level < len(cls.LEVELS):
            return cls.LEVELS[level]
        else:
            vollog.debug(f"Level {level} unknown")
            return str(level)

    @classmethod
    def get_facility_text(cls, facility: int) -> str:
        if facility < len(cls.FACILITIES):
            return cls.FACILITIES[facility]
        else:
            vollog.debug(f"Facility {facility} unknown")
            return str(facility)


class Kmsg_pre_3_5(ABCKmsg):
    """The kernel ring buffer (log_buf) is a char array that sequentially stores
    log lines, each separated by newline (LF) characters. i.e:
        <6>[ 9565.250411] line1!\n<6>[ 9565.250412] line2\n...
    """

    @classmethod
    def symtab_checks(cls, vmlinux) -> bool:
        return (
            vmlinux.has_symbol("log_end")
            and not vmlinux.has_symbol("log_first_idx")
            and not (
                vmlinux.has_type("log")
                and vmlinux.get_type("log").has_member("ts_nsec")
            )
        )

    def run(self) -> Iterator[Tuple[str, str, str, str, str]]:
        log_buf_ptr = self.vmlinux.object_from_symbol(symbol_name="log_buf")
        log_buf_len = self.vmlinux.object_from_symbol(symbol_name="log_buf_len")
        log_buf = utility.pointer_to_string(log_buf_ptr, count=log_buf_len)
        log_end = self.vmlinux.object_from_symbol(symbol_name="log_end")

        if log_end > log_buf_len:
            start = log_end - log_buf_len
            first_half = log_buf[start:]
            second_half = log_buf[:start]
            log_buf = first_half + second_half

        log_buf_lines = log_buf.splitlines()

        for log_buf_line in log_buf_lines:
            m = re.match(r"<(\d+)>\[\s*(\d+\.\d+)\]\s(.*?)$", log_buf_line)
            if not m:
                # If there was a wrap-around in the ring buffer, it will find
                # remnants at the top. As those remnants do not conform to the
                # expected line format, they are discarded
                continue

            level_facility_str, timestamp_str, line = m.groups()
            level_facility = int(level_facility_str)
            # The lower 3 bit are the log level, the rest are the log facility
            level = level_facility & 7
            facility = level_facility >> 3
            level_txt = self.get_level_text(level)
            facility_txt = self.get_facility_text(facility)
            caller = renderers.NotAvailableValue()
            yield facility_txt, level_txt, timestamp_str, caller, line


class Kmsg_3_5_to_3_11(ABCKmsg):
    """While 'log_buf' is declared as a pointer and '__log_buf' as a char array,
    it essentially holds an array of 'log' structs.
    """

    @classmethod
    def symtab_checks(cls, vmlinux) -> bool:
        return (
            vmlinux.has_type("log")
            and vmlinux.get_type("log").has_member("ts_nsec")
            and vmlinux.has_symbol("log_first_idx")
        )

    def _get_log_struct_name(self):
        return "log"

    def get_text_from_log(self, msg) -> str:
        log_struct_name = self._get_log_struct_name()
        log_struct_size = self.vmlinux.get_type(log_struct_name).size
        msg_offset = msg.vol.offset + log_struct_size
        return self.get_string(msg_offset, msg.text_len)

    def get_log_lines(self, msg) -> Generator[str, None, None]:
        if msg.text_len > 0:
            text = self.get_text_from_log(msg)
            yield from text.splitlines()

    def get_dict_lines(self, msg) -> Generator[str, None, None]:
        if msg.dict_len == 0:
            return None

        log_struct_name = self._get_log_struct_name()
        log_struct_size = self.vmlinux.get_type(log_struct_name).size
        dict_offset = msg.vol.offset + log_struct_size + msg.text_len
        dict_data = self._context.layers[self.layer_name].read(
            dict_offset, msg.dict_len
        )
        for chunk in dict_data.split(b"\x00"):
            yield " " + chunk.decode()

    def run(self) -> Iterator[Tuple[str, str, str, str, str]]:
        # First, the ring buffer size is determined in the kernel configuration
        # by CONFIG_LOG_BUF_SHIFT. This static buffer is held in the '__log_buf'
        # global variable, with 'log_buf' serving as a pointer to it.
        # The user can also update this size using 'log_buf_len' in the
        # kernel boot parameters. Additionally, in SMP systems with over 64 CPUs,
        # the ring buffer size dynamically allocates based on the number of CPUs,
        # following CONFIG_LOG_CPU_MAX_BUF_SHIFT.
        # In the last two cases mentioned above, the 'log_buf' pointer is
        # updated to this new buffer. The original static buffer in '__log_buf'
        # remains unused. Therefore, it is crucial to read from 'log_buf' rather
        # than '__log_buf'.

        log_buf_ptr = self.vmlinux.object_from_symbol("log_buf")
        log_buf_len = self.vmlinux.object_from_symbol("log_buf_len")

        log_first_idx = int(self.vmlinux.object_from_symbol("log_first_idx"))
        log_next_idx = int(self.vmlinux.object_from_symbol("log_next_idx"))

        log_struct_name = self._get_log_struct_name()

        cur_idx = log_first_idx
        if log_first_idx < log_next_idx:
            end_idx = log_next_idx
        else:
            end_idx = log_buf_len

        while cur_idx < end_idx:
            msg_offset = log_buf_ptr + cur_idx  # type: ignore
            msg = self.vmlinux.object(object_type=log_struct_name, offset=msg_offset)
            if msg.len == 0:
                # As per kernel/printk.c:
                # A length == 0 for the next message indicates a wrap-around to
                # the beginning of the buffer.
                cur_idx = 0
                end_idx = log_next_idx
            else:
                facility, level, timestamp, caller = self.get_prefix(msg)
                level_txt = self.get_level_text(level)
                facility_txt = self.get_facility_text(facility)

                for line in self.get_log_lines(msg):
                    yield facility_txt, level_txt, timestamp, caller, line
                for line in self.get_dict_lines(msg):
                    yield facility_txt, level_txt, timestamp, caller, line

                cur_idx += msg.len


class Kmsg_3_11_to_5_10(Kmsg_3_5_to_3_11):
    """Starting from version 3.11, the struct 'log' was renamed to 'printk_log'.
    While 'log_buf' is declared as a pointer and '__log_buf' as a char array,
    it essentially holds an array of 'printk_log' structs.
    """

    @classmethod
    def symtab_checks(cls, vmlinux) -> bool:
        return vmlinux.has_type("printk_log")

    def _get_log_struct_name(self):
        return "printk_log"


class Kmsg_5_10_to_(ABCKmsg):
    """In 5.10 the kernel ring buffer implementation changed.
    Previously only one process should read /proc/kmsg and it is permanently
    open and periodically read by the syslog daemon.
    A high level structure 'printk_ringbuffer' was added to represent the printk
    ring buffer which actually contains two ring buffers. The descriptor ring
    'desc_ring' contains the records' metadata, text offsets and states.
    The data block ring 'text_data_ring' contains the records' text strings.
    A pointer to the high level structure is kept in the prb pointer which is
    initialized to a static ring buffer.

    .. code-block:: c

        static struct printk_ringbuffer *prb = &printk_rb_static;

    In SMP systems with more than 64 CPUs this ring buffer size is dynamically
    allocated according the number of CPUs based on the value of
    CONFIG_LOG_CPU_MAX_BUF_SHIFT. The prb pointer is updated consequently to
    this dynamic ring buffer in setup_log_buf().

    .. code-block:: c

        prb = &printk_rb_dynamic;

    Behind scenes, 'log_buf' is still used as external buffer.
    When the static 'printk_ringbuffer' struct is initialized, _DEFINE_PRINTKRB
    sets text_data_ring.data pointer to the address in 'log_buf' which points
    to the static buffer '__log_buf'.
    If a dynamic ring buffer takes place, setup_log_buf() sets
    text_data_ring.data of 'printk_rb_dynamic' to the new allocated external
    buffer via the 'prb_init' function.
    In that case, the original external static buffer in '__log_buf' and
    'printk_rb_static' are unused.

    .. code-block:: c

        new_log_buf = memblock_alloc(new_log_buf_len, LOG_ALIGN);
        prb_init(&printk_rb_dynamic, new_log_buf, ...);
        log_buf = new_log_buf;
        prb = &printk_rb_dynamic;

    See printk.c and printk_ringbuffer.c in kernel/printk/ folder for more
    details.
    """

    @classmethod
    def symtab_checks(cls, vmlinux) -> bool:
        return vmlinux.has_symbol("prb")

    def get_text_from_data_ring(self, text_data_ring, desc, info) -> str:
        text_data_sz = text_data_ring.size_bits
        text_data_mask = 1 << text_data_sz

        begin = desc.text_blk_lpos.begin % text_data_mask
        end = desc.text_blk_lpos.next % text_data_mask

        # This record doesn't contain text
        if begin & 1:
            return ""

        # This means a wrap-around to the beginning of the buffer
        if begin > end:
            begin = 0

        # Each element in the ringbuffer is "ID + data".
        # See prb_data_ring struct
        desc_id_size = self.long_unsigned_int_size
        text_start = begin + desc_id_size
        offset = text_data_ring.data + text_start

        # Safety first ;)
        text_len = min(info.text_len, end - begin)

        return self.get_string(offset, text_len)

    def get_log_lines(self, text_data_ring, desc, info) -> Generator[str, None, None]:
        text = self.get_text_from_data_ring(text_data_ring, desc, info)
        yield from text.splitlines()

    def get_dict_lines(self, info) -> Generator[str, None, None]:
        dict_text = utility.array_to_string(info.dev_info.subsystem)
        if dict_text:
            yield f" SUBSYSTEM={dict_text}"

        dict_text = utility.array_to_string(info.dev_info.device)
        if dict_text:
            yield f" DEVICE={dict_text}"

    def run(self) -> Iterator[Tuple[str, str, str, str, str]]:
        # static struct printk_ringbuffer *prb = &printk_rb_static;
        ringbuffers = self.vmlinux.object_from_symbol("prb").dereference()

        desc_ring = ringbuffers.desc_ring
        text_data_ring = ringbuffers.text_data_ring
        desc_count = 1 << desc_ring.count_bits

        array_type = self.vmlinux.symbol_table_name + constants.BANG + "array"

        desc_arr = self._context.object(
            array_type,
            offset=desc_ring.descs,
            subtype=self.vmlinux.get_type("prb_desc"),
            count=desc_count,
            layer_name=self.layer_name,
        )

        info_arr = self._context.object(
            array_type,
            offset=desc_ring.infos,
            subtype=self.vmlinux.get_type("printk_info"),
            count=desc_count,
            layer_name=self.layer_name,
        )

        # See kernel/printk/printk_ringbuffer.h
        desc_state_var_bytes_sz = self.long_unsigned_int_size
        desc_state_var_bits_sz = desc_state_var_bytes_sz * 8
        desc_flags_shift = desc_state_var_bits_sz - 2
        desc_flags_mask = 3 << desc_flags_shift
        desc_id_mask = ~desc_flags_mask

        cur_id = desc_ring.tail_id.counter
        end_id = None
        while cur_id != end_id:
            end_id = desc_ring.head_id.counter
            desc = desc_arr[cur_id % desc_count]  # type: ignore
            info = info_arr[cur_id % desc_count]  # type: ignore
            desc_state = DescStateEnum((desc.state_var.counter >> desc_flags_shift) & 3)
            if desc_state in (
                DescStateEnum.desc_committed,
                DescStateEnum.desc_finalized,
            ):
                facility, level, timestamp, caller = self.get_prefix(info)
                level_txt = self.get_level_text(level)
                facility_txt = self.get_facility_text(facility)

                for line in self.get_log_lines(text_data_ring, desc, info):
                    yield facility_txt, level_txt, timestamp, caller, line
                for line in self.get_dict_lines(info):
                    yield facility_txt, level_txt, timestamp, caller, line

            cur_id += 1
            cur_id &= desc_id_mask


class Kmsg(plugins.PluginInterface):
    """Kernel log buffer reader"""

    _required_framework_version = (2, 0, 0)

    _version = (1, 0, 1)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    def _generator(self) -> Iterator[Tuple[int, Tuple[str, str, str, str, str]]]:
        for values in ABCKmsg.run_all(context=self.context, config=self.config):
            yield (0, values)

    def run(self):
        return renderers.TreeGrid(
            [
                ("facility", str),
                ("level", str),
                ("timestamp", str),
                ("caller", str),
                ("line", str),
            ],
            self._generator(),
        )  # type: ignore
