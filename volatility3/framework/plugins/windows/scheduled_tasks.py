# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import base64
import binascii
import dataclasses
import datetime
import enum
import io
import itertools
import logging
import struct
import traceback
import unittest
from typing import Dict, Iterator, List, Optional, Tuple, Union

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import registry
from volatility3.framework.renderers import conversion
from volatility3.framework.symbols.windows.extensions import registry as reg_extensions
from volatility3.plugins import timeliner
from volatility3.plugins.windows.registry import hivelist

vollog = logging.getLogger(__name__)

# Reference: https://cyber.wtf/2022/06/01/windows-registry-analysis-todays-episode-tasks/


class TimeMode(enum.Enum):
    """
    Enumeration containing the different time modes that a 'Time' trigger can be configured to run in.
    """

    Once = "Once"

    # run at <start_boundary> and repeat every <data1> days
    Daily = "Daily"

    # run on days of week <(data2 as day_of_week bitmap)> every <data1> weeks starting at <start_boundary>
    Weekly = "Weekly"

    # run in months <(data3 as months bitmap> on days <(data2:data1 as day in month bitmap)>
    # starting at <start_boundary>
    DaysInMonths = "Days In Months"

    # run in months <(data3 as months bitmap> in weeks <(data2 as week bitmap)>
    # on days <(data1 as day_of_week bitmap)> starting at <start_boundary>
    DaysInWeeksInMonths = "Days In Weeks in Months"

    Unknown = "Unknown"


class ActionType(enum.Enum):
    """
    Enumeration that maps action types to their magic number encodings
    """

    Exe = 0x6666
    ComHandler = 0x7777
    Email = 0x8888
    MessageBox = 0x9999


class TriggerType(enum.Enum):
    """
    Enumeration that maps trigger types to their magic number encodings
    """

    WindowsNotificationFacility = 0x6666
    Session = 0x7777
    Registration = 0x8888
    Logon = 0xAAAA
    Event = 0xCCCC
    Time = 0xDDDD
    Idle = 0xEEEE
    Boot = 0xFFFF


class Weekday(enum.Enum):
    """
    Enumeration that contains bitwise values for days of the week.
    """

    Sunday = 0x1
    Monday = 0x2
    Tuesday = 0x4
    Wednesday = 0x8
    Thursday = 0x10
    Friday = 0x20
    Saturday = 0x40


class Months(enum.Enum):
    """
    Enumeration that contains bitwise values for months of the year.
    """

    January = 0x1
    February = 0x2
    March = 0x4
    April = 0x8
    May = 0x10
    June = 0x20
    July = 0x40
    August = 0x80
    September = 0x100
    October = 0x200
    November = 0x400
    December = 0x800


class SidType(enum.Enum):
    """
    Enumeration that maps SID types to their encoded integer values
    """

    User = 1
    Group = 2
    Domain = 3
    Alias = 4
    WellKnownGroup = 5
    DeletedAccount = 6
    Invalid = 7
    Unknown = 8
    Computer = 9
    Label = 10
    LogonSession = 11


@dataclasses.dataclass
class TaskSchedulerTime:
    """
    A class containing datetime information about when a task will run
    """

    is_localized: bool
    filetime: Optional[datetime.datetime]


@dataclasses.dataclass
class TaskSchedulerTimePeriod:
    """
    Class containing information delimiting time periods within scheduled tasks.
    """

    years: int
    months: int
    weeks: int
    days: int
    hours: int
    minutes: int
    seconds: int


JOB_BUCKET_FLAGS = {
    0x2: "Run only if idle",
    0x4: "Restart on idle",
    0x8: "Stop on idle end",
    0x10: "Disallow start if on batteries",
    0x20: "Stop if going on batteries",
    0x40: "Start when available",
    0x80: "Run only if network available",
    0x100: "Allow start on demand",
    0x200: "Wake to run",
    0x400: "Execute parallel",
    0x800: "Execute stop existing",
    0x1000: "Execute queue",
    0x2000: "Execute ignore new",
    0x4000: "Logon type s4u",
    0x10000: "Logon type InteractiveToken",
    0x40000: "Logon type Password",
    0x80000: "Logon type InteractiveTokenOrPassword",
    0x400000: "Enabled",
    0x800000: "Hidden",
    0x1000000: "Runlevel highest available",
    0x2000000: "Task",
    0x4000000: "Version",
    0x8000000: "Token SID type none",
    0x10000000: "Token SID type unrestricted",
    0x20000000: "Interval",
    0x40000000: "Allow hard terminate",
}

NULL = "\u0000"


class _ScheduledTasksReader(io.BytesIO):

    def read_task_scheduler_time(self) -> Optional[Tuple[bool, datetime.datetime]]:
        is_localized = bool(self.read_aligned_u1())
        filetime = self.decode_filetime()
        if filetime is None:
            return None
        return is_localized, filetime

    def read_filetime(self) -> Optional[datetime.datetime]:
        return datetime.datetime.now()

    def seek_relative(self, offset) -> int:
        return self.seek(offset, io.SEEK_CUR)

    def read_bool(self, aligned=False) -> Optional[bool]:
        try:
            val = struct.unpack("?", self.read(1))[0]
            if aligned:
                self.seek(7)
            return val
        except struct.error:
            return None

    def decode_filetime(self) -> Optional[datetime.datetime]:
        filetime = self.read_u8()
        if filetime is None:
            return None

        if filetime == 0 or filetime == 0xFFFFFFFFFFFFFFFF:
            return None
        filetime = conversion.wintime_to_datetime(filetime)
        if isinstance(filetime, datetime.datetime):
            return filetime
        else:
            return None

    def _read_uint(
        self, size: int, format: str, aligned: bool = False
    ) -> Optional[int]:
        try:
            val = struct.unpack(format, self.read(size))[0]
            if aligned:
                self.seek(8 - size, io.SEEK_CUR)
            return val
        except struct.error:
            return None

    def read_aligned_u1(self) -> Optional[int]:
        return self._read_uint(1, "B", True)

    def read_u2(self) -> Optional[int]:
        return self._read_uint(2, "<H")

    def read_aligned_u2(self) -> Optional[int]:
        return self._read_uint(2, "<H", True)

    def read_u4(self) -> Optional[int]:
        return self._read_uint(4, "<I")

    def read_u8(self) -> Optional[int]:
        return self._read_uint(8, "<Q")

    def read_aligned_u4(self) -> Optional[int]:
        return self._read_uint(4, "<I", True)

    def read_buffer(self, aligned=False) -> Optional[bytes]:
        count = self.read_u4() if not aligned else self.read_aligned_u4()
        if count is None:
            return None
        data = self.read(count)
        if aligned:
            self.seek((8 - (count % 8)) % 8, io.SEEK_CUR)
        return data

    def read_bstring(self, aligned=False) -> Optional[str]:
        size = self.read_u4() if not aligned else self.read_aligned_u4()
        if size is None:
            return None
        try:
            raw = self.read(size)
            val = raw.decode("utf-16le", errors="replace").rstrip(NULL) or None
        except UnicodeDecodeError:
            val = None

        if aligned:
            self.seek((8 - (size % 8)) % 8, io.SEEK_CUR)

        return val

    def read_aligned_bstring_expand_sz(self) -> Optional[str]:
        # type: () -> Optional[str]
        sz = self.read_aligned_u4()
        if sz is None:
            return None
        byte_count = sz * 2 + 2

        if sz == 0:
            return None

        try:
            content = self.read(byte_count).decode("utf-16le")
        except UnicodeDecodeError:
            content = None

        self.seek((8 - (byte_count % 8)) % 8, io.SEEK_CUR)
        return content.rstrip("\x00") if content is not None else None

    def read_tstimeperiod(self) -> Optional[TaskSchedulerTimePeriod]:
        values = (
            self.read_u2(),
            self.read_u2(),
            self.read_u2(),
            self.read_u2(),
            self.read_u2(),
            self.read_u2(),
            self.read_u2(),
        )

        if any(value is None for value in values):
            return None

        return TaskSchedulerTimePeriod(*values)


def _build_guid_name_map(key: reg_extensions.CM_KEY_NODE) -> Dict[str, str]:
    mapping = {}
    task_id_value = None
    for value in key.get_values():
        try:
            if value.get_name() == "Id":
                task_id_value = value
                break
        except exceptions.InvalidAddressException:
            continue

    if (
        task_id_value is not None
        and task_id_value.get_type() == reg_extensions.RegValueTypes.REG_SZ
    ):
        try:
            id_str = task_id_value.decode_data()
        except exceptions.InvalidAddressException:
            id_str = None

        if isinstance(id_str, bytes):
            mapping[id_str.decode("utf-16le", errors="replace").rstrip(NULL)] = str(
                key.get_name()
            )

    for subkey in key.get_subkeys():
        mapping.update(_build_guid_name_map(subkey))
    return mapping


@dataclasses.dataclass
class TaskAction:
    action_type: ActionType
    action: str
    action_args: Optional[str]
    working_directory: Optional[str]

    @classmethod
    def decode_messagebox_action(
        cls, reader: _ScheduledTasksReader
    ) -> Optional["TaskAction"]:
        caption, content = reader.read_bstring(), reader.read_bstring()
        return cls(
            ActionType.MessageBox,
            f'"{caption or "<Unknown>"}": {content or "<Unknown>"}',
            None,
            None,
        )

    @classmethod
    def _decode_exe_action(
        cls, reader: _ScheduledTasksReader, version: int
    ) -> Optional["TaskAction"]:
        command = reader.read_bstring()
        args = reader.read_bstring()
        if command is None or args is None:
            return None

        workdir = reader.read_bstring()
        if version == 3:
            _flags = reader.read_u2()

        return cls(ActionType.Exe, command, args, workdir)

    @classmethod
    def _decode_email_action(
        cls, reader: _ScheduledTasksReader
    ) -> Optional["TaskAction"]:
        props = {
            "From": reader.read_bstring(),
            "To": reader.read_bstring(),
            "Cc": reader.read_bstring(),
            "Bcc": reader.read_bstring(),
            "Reply_to": reader.read_bstring(),
            "Server": reader.read_bstring(),
            "Subject": reader.read_bstring(),
            "Body": reader.read_bstring(),
        }

        num_attachment_filenames = reader.read_u4()
        if num_attachment_filenames is not None:

            attachment_filenames = [
                reader.read_bstring() for _ in range(num_attachment_filenames)
            ]

            props["Attachments"] = (
                "<"
                + ", ".join(
                    filename
                    for filename in attachment_filenames
                    if filename is not None
                )
                + ">"
            )

        num_headers = reader.read_u4()
        if num_headers is not None:
            headers = [
                (reader.read_bstring(), reader.read_bstring())
                for _ in range(num_headers)
            ]

            props["Headers"] = (
                "<"
                + ", ".join(
                    f"{field}: {value}"
                    for field, value in headers
                    if field is not None and value is not None
                )
                + ">"
            )

        cls(
            ActionType.Email,
            ", ".join(
                f"{key}: {value}" for key, value in props.items() if value is not None
            ),
            None,
            None,
        )

    @classmethod
    def _decode_comhandler_action(
        cls, reader: _ScheduledTasksReader
    ) -> Optional["TaskAction"]:
        guid_raw = reader.read(16)
        if not guid_raw and len(guid_raw) == 16:
            return None
        clsid = conversion.windows_bytes_to_guid(guid_raw)
        args = reader.read_bstring()

        return cls(ActionType.ComHandler, clsid, args, None)


@dataclasses.dataclass
class _ScheduledTaskEntry:
    name: Union[str, interfaces.renderers.BaseAbsentValue]
    principal_id: Union[str, interfaces.renderers.BaseAbsentValue]
    display_name: Union[str, interfaces.renderers.BaseAbsentValue]
    enabled: Union[bool, interfaces.renderers.BaseAbsentValue]
    creation_time: Union[datetime.datetime, interfaces.renderers.BaseAbsentValue]
    last_run_time: Union[datetime.datetime, interfaces.renderers.BaseAbsentValue]
    last_successful_run_time: Union[
        datetime.datetime, interfaces.renderers.BaseAbsentValue
    ]
    trigger_type: Union[str, interfaces.renderers.BaseAbsentValue]
    trigger_description: Union[str, interfaces.renderers.BaseAbsentValue]
    action_type: Union[str, interfaces.renderers.BaseAbsentValue]
    action_description: Union[str, interfaces.renderers.BaseAbsentValue]
    action_args: Union[str, interfaces.renderers.BaseAbsentValue]
    action_context: Union[str, interfaces.renderers.BaseAbsentValue]
    working_directory: Union[str, interfaces.renderers.BaseAbsentValue]
    guid: str


@dataclasses.dataclass
class _JobSchedule:
    start_boundary: Optional[datetime.datetime]
    end_boundary: Optional[datetime.datetime]
    repetition_interval_secs: Optional[int]
    repetition_duration_secs: Optional[int]
    execution_time_limit_secs: Optional[int]
    mode: Optional[TimeMode]
    data1: Optional[int]
    data2: Optional[int]
    data3: Optional[int]
    stop_tasks_at_duration_end: Optional[int]
    is_enabled: Optional[bool]
    max_delay_seconds: Optional[int]

    def get_description(self) -> Optional[str]:
        if self.mode == TimeMode.Once:
            return "Run one time starting at {}".format(
                self.start_boundary.isoformat()
                if self.start_boundary is not None
                else "<UNKNOWN>"
            )

        elif self.mode == TimeMode.Daily:
            if self.data1 is None:
                return None
            return "Run at {} and repeat every {} days".format(
                (
                    self.start_boundary.isoformat()
                    if self.start_boundary is not None
                    else "<UNKNOWN>"
                ),
                self.data1,
            )

        elif self.mode == TimeMode.Weekly:
            if self.data2 is None:
                return None

            days = [k.name for k in Weekday if k.value & self.data2]
            return "Run on {} every {} weeks starting at {}".format(
                ", ".join(days),
                self.data1,
                (
                    self.start_boundary.isoformat()
                    if self.start_boundary is not None
                    else "<UNKNOWN>"
                ),
            )
        elif self.mode == TimeMode.DaysInMonths:
            if self.data2 is None or self.data1 is None or self.data3 is None:
                return None
            months = [month.name for month in Months if month.value & self.data3]
            days_bitmap = (self.data2 << 16) + self.data1
            days = [str(v + 1) for v in range(31) if (1 << v) & days_bitmap]
            return "Run in months {} on days {} starting at {}".format(
                ", ".join(months),
                ", ".join(days),
                (
                    self.start_boundary.isoformat()
                    if self.start_boundary is not None
                    else "<UNKNOWN>"
                ),
            )
        elif self.mode == TimeMode.DaysInWeeksInMonths:
            if self.data1 is None or self.data2 is None or self.data3 is None:
                return None

            months = [month.name for month in Months if month.value & self.data3]
            weeks = [str(v + 1) for v in range(5) if (v << 1) & self.data2]
            days = [day.name for day in Weekday if day.value & self.data1]
            return "Run in months {} in weeks {} on days {} starting at {}".format(
                ", ".join(months),
                ", ".join(weeks),
                ", ".join(days),
                (
                    self.start_boundary.isoformat()
                    if self.start_boundary is not None
                    else "<UNKNOWN>"
                ),
            )
        else:
            return None

    @classmethod
    def decode(cls, reader: _ScheduledTasksReader) -> Optional["_JobSchedule"]:
        start_boundary = reader.read_task_scheduler_time()
        end_boundary = reader.read_task_scheduler_time()

        _ = reader.read_task_scheduler_time()
        repetition_interval_secs = reader.read_u4()
        repetition_duration_secs = reader.read_u4()
        execution_time_limit_secs = reader.read_u4()
        mode_index = reader.read_u4()
        try:
            if mode_index is not None:
                mode = list(TimeMode)[mode_index]
            else:
                mode = None
        except IndexError:
            mode = TimeMode.Unknown
        data1 = reader.read_u2()
        data2 = reader.read_u2()
        data3 = reader.read_u2()

        reader.seek(2, io.SEEK_CUR)  # pad
        stop_tasks_at_duration_end = reader.read_bool()
        is_enabled = reader.read_bool()
        reader.seek(6, io.SEEK_CUR)  # pad (2) + unknown (4)
        max_delay_seconds = reader.read_u4()
        reader.seek(4, io.SEEK_CUR)  # pad

        return cls(
            start_boundary[1] if start_boundary is not None else None,
            end_boundary[1] if end_boundary is not None else None,
            repetition_interval_secs,
            repetition_duration_secs,
            execution_time_limit_secs,
            mode,
            data1,
            data2,
            data3,
            stop_tasks_at_duration_end,
            is_enabled,
            max_delay_seconds,
        )


def decode_sid(data: bytes) -> Optional[str]:
    """
    Decodes a windows SID from variable-length raw bytes

    Returns the string representation of the SID if decoding was successful, or None
    if the data could not be parsed due to an insufficent number of bytes.
    """
    try:
        revision, subid_count, id_authority = struct.unpack(
            ">BBQ", data[:2] + b"\x00\x00" + data[2:8]
        )
        subauthorities = struct.unpack(
            "<" + "I" * subid_count, data[8 : 8 + subid_count * 4]
        )
        sid_string = "S-" + "-".join(
            [str(item) for item in [revision, id_authority] + list(subauthorities)]
        )
    except struct.error:
        return None

    return sid_string


@dataclasses.dataclass
class UserInfo:
    sid_type: Optional[SidType]
    sid: Optional[str]
    username: Optional[str]

    @classmethod
    def _decode(cls, reader: _ScheduledTasksReader) -> Optional["UserInfo"]:
        skip_user = reader.read_aligned_u1() != 0
        if not skip_user:
            skip_sid = reader.read_aligned_u1() != 0
        else:
            skip_sid = None

        sid_type = None
        sid = None
        if not skip_user and not skip_sid:
            try:
                sid_type = SidType(reader.read_aligned_u4())
            except ValueError:
                sid_type = SidType.Unknown

            sid_raw = reader.read_buffer(aligned=True)
            if sid_raw is None:
                return None
            sid = decode_sid(sid_raw)

        username = reader.read_bstring(aligned=True) if not skip_user else None

        return UserInfo(sid_type, sid, username)


@dataclasses.dataclass
class OptionalSettings:
    IdleDurationSeconds: int
    idleWaitTimeoutSeconds: int
    ExecutionTimeLimitSeconds: int
    DeleteExpiredTaskAfter: int
    Priority: int
    RestartOnFailureDelay: int
    RestartOnFailureRetries: int
    NetworkId: bytes
    Privileges: Optional[List[str]]
    Periodicity: Optional[TaskSchedulerTimePeriod]
    Deadline: Optional[TaskSchedulerTimePeriod]
    Exclusive: Optional[bool]

    @classmethod
    def _decode(cls, reader: _ScheduledTasksReader) -> Optional["OptionalSettings"]:
        LEN_WITH_PRIVILEGES = 0x38
        LEN_WITH_TIME_PERIODS = 0x58
        length = reader.read_aligned_u4()
        if length == 0:
            return None

        base_values = (
            reader.read_u4(),
            reader.read_u4(),
            reader.read_u4(),
            reader.read_u4(),
            reader.read_u4(),
            reader.read_u4(),
            reader.read_u4(),
            binascii.hexlify(reader.read(16)),
        )

        if any(value is None for value in base_values):
            return None

        reader.seek(4, io.SEEK_CUR)  # padding

        privileges = None
        periodicity = None
        deadline = None
        exclusive = None
        if length == LEN_WITH_PRIVILEGES or length == LEN_WITH_TIME_PERIODS:
            privileges_raw = reader.read_u8()
            if privileges_raw is None:
                return None
            privileges = [
                priv.name for priv in Privileges if priv.value & privileges_raw
            ]
        if length == LEN_WITH_TIME_PERIODS:
            periodicity = reader.read_tstimeperiod()
            deadline = reader.read_tstimeperiod()
            exclusive = reader.read_bool()
            reader.seek(3, io.SEEK_CUR)  # padding

        return OptionalSettings(
            *base_values, privileges, periodicity, deadline, exclusive
        )


@dataclasses.dataclass
class JobBucket:
    flags: List[str]
    crc32: int
    principal_id: Optional[str]
    display_name: Optional[str]
    user_info: Optional[UserInfo]
    optional_settings: Optional[OptionalSettings]

    @classmethod
    def _decode(
        cls, reader: _ScheduledTasksReader, version: int
    ) -> Optional["JobBucket"]:
        flags_raw = reader.read_aligned_u4()
        if flags_raw is None:
            return None
        flags = [y for x, y in JOB_BUCKET_FLAGS.items() if x & flags_raw]
        crc32 = reader.read_aligned_u4()
        if crc32 is None:
            return None

        principal_id = None
        display_name = None
        if version >= 0x16:
            principal_id = reader.read_bstring(aligned=True)
        if version >= 0x17:
            display_name = reader.read_bstring(aligned=True)

        user_info = UserInfo._decode(reader)
        optional_settings = OptionalSettings._decode(reader)

        return JobBucket(
            flags, crc32, principal_id, display_name, user_info, optional_settings
        )


class Privileges(enum.Enum):
    SeCreateTokenPrivilege = 0x4
    SeAssignPrimaryTokenPrivilege = 0x8
    SeLockMemoryPrivilege = 0x10
    SeIncreaseQuotaPrivilege = 0x20
    SeMachineAccountPrivilege = 0x40
    SeTcbPrivilege = 0x80
    SeSecurityPrivilege = 0x100
    SeTakeOwnershipPrivilege = 0x200
    SeLoadDriverPrivilege = 0x400
    SeSystemProfilePrivilege = 0x800
    SeSystemtimePrivilege = 0x1000
    SeProfileSingleProcessPrivilege = 0x2000
    SeIncreaseBasePriorityPrivilege = 0x4000
    SeCreatePagefilePrivilege = 0x8000
    SeCreatePermanentPrivilege = 0x10000
    SeBackupPrivilege = 0x20000
    SeRestorePrivilege = 0x40000
    SeShutdownPrivilege = 0x80000
    SeDebugPrivilege = 0x100000
    SeAuditPrivilege = 0x200000
    SeSystemEnvironmentPrivilege = 0x400000
    SeChangeNotifyPrivilege = 0x800000
    SeRemoteShutdownPrivilege = 0x1000000
    SeUndockPrivilege = 0x2000000
    SeSyncAgentPrivilege = 0x4000000
    SeEnableDelegationPrivilege = 0x8000000
    SeManageVolumePrivilege = 0x10000000
    SeImpersonatePrivilege = 0x20000000
    SeCreateGlobalPrivilege = 0x40000000
    SeTrustedCredManAccessPrivilege = 0x80000000
    SeRelabelPrivilege = 0x100000000
    SeIncreaseWorkingSetPrivilege = 0x200000000
    SeTimeZonePrivilege = 0x400000000
    SeCreateSymbolicLinkPrivilege = 0x800000000
    SeDelegateSessionUserImpersonatePrivilege = 0x1000000000


class SessionState(enum.Enum):
    ConsoleConnect = 1
    ConsoleDisconnect = 2
    RemoteConnect = 3
    RemoteDisconnect = 4
    SessionLock = 5
    SessionUnlock = 6
    Unknown = "Unknown"


@dataclasses.dataclass
class TaskTrigger:
    start_boundary: Optional[datetime.datetime]
    end_boundary: Optional[datetime.datetime]
    repetition_interval_seconds: Optional[int]
    enabled: Optional[bool]
    trigger_type: TriggerType
    description: Optional[str]

    @classmethod
    def _decode_generic_trigger(
        cls, reader: _ScheduledTasksReader, version: int, trigger_type: TriggerType
    ) -> Optional["TaskTrigger"]:
        start_boundary = reader.read_task_scheduler_time()
        end_boundary = reader.read_task_scheduler_time()

        _ = reader.read_u4()  # delay seconds
        _ = reader.read_u4()  # timeout seconds

        repetition_interval_secs = reader.read_u4()
        _ = reader.read_u4()  # reptition duration seconds
        _ = reader.read_u4()  # repetition duration seconds 2

        _ = reader.read_bool()  # stop at duration end
        reader.seek(3, io.SEEK_CUR)
        trigger_enabled = bool(reader.read_aligned_u1())
        reader.seek(8, io.SEEK_CUR)  # unknown field

        if version >= 0x16:
            cur = reader.tell()
            _ = reader.read_bstring()  # trigger id
            reader.seek((8 - (reader.tell() - cur)) % 8, io.SEEK_CUR)  # pad to block

        return cls(
            start_boundary[1] if start_boundary is not None else None,
            end_boundary[1] if end_boundary is not None else None,
            repetition_interval_secs,
            trigger_enabled,
            trigger_type,
            f"{trigger_type.name} trigger",
        )

    @classmethod
    def _decode_logon_trigger(
        cls, reader: _ScheduledTasksReader, version: int
    ) -> Optional["TaskTrigger"]:
        base = cls._decode_generic_trigger(reader, version, TriggerType.Logon)
        if base is None:
            return None

        user = UserInfo._decode(reader)
        if user is not None and user.username is not None:
            base.description = f"{user.username}: {user.sid} ({user.sid_type})"

        return base

    @classmethod
    def _decode_session_trigger(
        cls, reader: _ScheduledTasksReader, version: int
    ) -> Optional["TaskTrigger"]:
        base = cls._decode_generic_trigger(reader, version, TriggerType.Session)
        if base is None:
            return None
        session_type_raw = reader.read_u4()
        reader.seek(4, io.SEEK_CUR)

        try:
            session_type = SessionState(session_type_raw)
        except ValueError:
            session_type = SessionState.Unknown

        user_info = UserInfo._decode(reader)
        if user_info is not None and user_info.username is not None:
            base.description = f"{session_type.name} for user {user_info.username}"
        else:
            base.description = session_type.name

        return base

    @classmethod
    def _decode_time_trigger(
        cls, reader: _ScheduledTasksReader, version: int
    ) -> Optional["TaskTrigger"]:
        job_schedule = _JobSchedule.decode(reader)
        if job_schedule is None:
            return None

        if version >= 0x16:
            cur = reader.tell()
            _ = reader.read_bstring()  # trigger id
            reader.seek((8 - (reader.tell() - cur)) % 8, io.SEEK_CUR)  # pad to block

        return cls(
            job_schedule.start_boundary,
            job_schedule.end_boundary,
            job_schedule.repetition_interval_secs,
            job_schedule.is_enabled,
            TriggerType.Time,
            job_schedule.get_description() or None,
        )

    @classmethod
    def _decode_event_trigger(
        cls, reader: _ScheduledTasksReader, version: int
    ) -> Optional["TaskTrigger"]:
        base = cls._decode_generic_trigger(reader, version, TriggerType.Event)
        if base is None:
            return base

        subscription = reader.read_aligned_bstring_expand_sz()
        reader.seek(8, io.SEEK_CUR)  # 2 4-byte unknown fields
        reader.read_aligned_bstring_expand_sz()  # another unknown field
        len_value_queries = reader.read_aligned_u4()

        if len_value_queries is None:
            return base

        queries = [
            (
                reader.read_aligned_bstring_expand_sz(),
                reader.read_aligned_bstring_expand_sz(),
            )
            for _ in range(len_value_queries)
        ]
        valid = [(k, v) for (k, v) in queries if k is not None and v is not None]
        if base.description is None:
            base.description = "Event Trigger"
        base.description += f": Subscription: {subscription}, Queries: {str(valid)}"
        return base

    @classmethod
    def _decode_boot_trigger(
        cls, reader: _ScheduledTasksReader, version: int
    ) -> Optional["TaskTrigger"]:
        return cls._decode_generic_trigger(reader, version, TriggerType.Boot)

    @classmethod
    def _decode_wnf_trigger(
        cls, reader: _ScheduledTasksReader, version: int
    ) -> Optional["TaskTrigger"]:
        base = cls._decode_generic_trigger(
            reader, version, TriggerType.WindowsNotificationFacility
        )
        if base is None:
            return None

        state_name = binascii.hexlify(reader.read(8)).decode("ascii")
        datalen = reader.read_aligned_u4()
        _ = base64.b64encode(reader.read(datalen))  # state binary data
        base.description = f"WNF state {state_name}"
        return base

    @classmethod
    def _decode_idle_trigger(
        cls, reader: _ScheduledTasksReader, version: int
    ) -> Optional["TaskTrigger"]:
        return cls._decode_generic_trigger(reader, version, TriggerType.Logon)

    @classmethod
    def _decode_registration_trigger(
        cls, reader: _ScheduledTasksReader, version: int
    ) -> Optional["TaskTrigger"]:
        return cls._decode_generic_trigger(reader, version, TriggerType.Logon)


@dataclasses.dataclass
class TriggerSet:
    job_bucket: JobBucket
    triggers: List[TaskTrigger]

    @classmethod
    def decode(cls, data) -> Optional["TriggerSet"]:
        reader = _ScheduledTasksReader(data)

        version = reader.read_aligned_u1()
        _ = reader.read_task_scheduler_time()  # start boundary
        _ = reader.read_task_scheduler_time()  # end_boundary

        if version is None:
            return None

        job_bucket = JobBucket._decode(reader, version)
        if job_bucket is None:
            return None

        triggers = []

        while True:
            magic = reader.read_aligned_u4()
            if magic is None:
                break
            try:
                trigger_type = TriggerType(magic)
            except ValueError:
                vollog.warning(f"Invalid trigger magic {hex(magic)}")
                break

            if trigger_type == TriggerType.Logon:
                trigger = TaskTrigger._decode_logon_trigger(reader, version)
            elif trigger_type == TriggerType.Session:
                trigger = TaskTrigger._decode_session_trigger(reader, version)
            elif trigger_type == TriggerType.WindowsNotificationFacility:
                trigger = TaskTrigger._decode_wnf_trigger(reader, version)
            elif trigger_type == TriggerType.Boot:
                trigger = TaskTrigger._decode_boot_trigger(reader, version)
            elif trigger_type == TriggerType.Registration:
                trigger = TaskTrigger._decode_registration_trigger(reader, version)
            elif trigger_type == TriggerType.Event:
                trigger = TaskTrigger._decode_event_trigger(reader, version)
            elif trigger_type == TriggerType.Idle:
                trigger = TaskTrigger._decode_idle_trigger(reader, version)
            elif trigger_type == TriggerType.Time:
                trigger = TaskTrigger._decode_time_trigger(reader, version)
            else:
                vollog.warning(
                    f"Invalid trigger magic {hex(magic)} encountered at offset {hex(reader.tell() - 8)}, stopping parsing"
                )
                break
            triggers.append(trigger)

        return cls(job_bucket, triggers)


@dataclasses.dataclass
class ActionSet:
    actions: List[TaskAction]
    context: Optional[str]

    @classmethod
    def decode(cls, data: bytes) -> Optional["ActionSet"]:
        reader = _ScheduledTasksReader(data)
        actions = []

        version = reader.read_u2()
        if version is None:
            return None

        if version in [2, 3]:
            action_context = reader.read_bstring()
        else:
            action_context = None

        while True:
            magic = reader.read_u2()
            if magic is None:
                break

            _ = (
                reader.read_bstring()
            )  # action identifier, usually (but not always) empty

            if magic == ActionType.Email.value:
                action = TaskAction._decode_email_action(reader)
            elif magic == ActionType.Exe.value:
                action = TaskAction._decode_exe_action(reader, version)
            elif magic == ActionType.ComHandler.value:
                action = TaskAction._decode_comhandler_action(reader)
            elif magic == ActionType.MessageBox.value:
                action = TaskAction.decode_messagebox_action(reader)
            else:
                break
            actions.append(action)

        return cls(actions, action_context)


@dataclasses.dataclass
class DynamicInfo:
    """
    Contains information about execution history for this task,
    including timestamps and the last error code
    """

    creation_time: Optional[datetime.datetime]
    last_run_time: Optional[datetime.datetime]
    last_successful_run_time: Optional[datetime.datetime]
    last_error_code: Optional[int]

    @classmethod
    def decode(cls, data: bytes) -> Optional["DynamicInfo"]:
        """
        Decodes a DynamicInfo structure from RegBin value data.
        Raises a `ScheduledTaskDecodingError` if the magic bytes are invalid, but otherwise
        attempts to decode as much as possible without returning an error.
        """
        DYNAMICINFO_MAGIC = 3

        reader = _ScheduledTasksReader(data)
        magic = reader.read_u4()
        if magic != DYNAMICINFO_MAGIC:
            return None

        creation_time = reader.decode_filetime()
        last_run_time = reader.decode_filetime()

        reader.seek(4, io.SEEK_CUR)  # deprecated field 'TaskState'

        last_error_code = reader.read_u4()
        last_success_time = reader.decode_filetime()

        vollog.debug((creation_time, last_run_time, last_success_time))

        return cls(
            last_run_time,
            creation_time,
            last_success_time,
            last_error_code,
        )


class ScheduledTasks(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Decodes scheduled task information from the Windows registry, including
    information about triggers, actions, run times, and creation times.
    """

    _required_framework_version = (2, 11, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel33", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="hivelist", plugin=hivelist.HiveList, version=(1, 0, 0)
            ),
        ]

    def generate_timeline(
        self,
    ) -> Iterator[Tuple[str, timeliner.TimeLinerType, datetime.datetime]]:
        for _, task in self._generator():
            if isinstance(task.last_run_time, datetime.datetime):
                yield f"ScheduledTasks: task action {task.action_description} with trigger {task.trigger_description} ran", timeliner.TimeLinerType.ACCESSED, task.last_run_time
            if isinstance(task.last_successful_run_time, datetime.datetime):
                yield f"ScheduledTasks: task action {task.action_description} with trigger {task.trigger_description} ran successfully", timeliner.TimeLinerType.ACCESSED, task.last_successful_run_time
            if isinstance(task.creation_time, datetime.datetime):
                yield f"ScheduledTasks: Creation Time for task {task.guid} with trigger {task.trigger_description or '<UNKNOWN>'}", timeliner.TimeLinerType.CREATED, task.creation_time

    @classmethod
    def get_software_hive(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        kernel: interfaces.context.ModuleInterface,
    ) -> Optional[registry.RegistryHive]:
        """Retrieves the `Amcache.hve` registry hive from the kernel module, if it can be located."""
        return next(
            hivelist.HiveList.list_hives(
                context=context,
                base_config_path=interfaces.configuration.path_join(
                    config_path, "hivelist"
                ),
                layer_name=kernel.layer_name,
                symbol_table=kernel.symbol_table_name,
                filter_string="SOFTWARE",
            ),
            None,
        )

    @classmethod
    def parse_actions_value(
        cls, actions_value: reg_extensions.CM_KEY_VALUE
    ) -> Optional[ActionSet]:
        """Parses File entries from the Windows 8 `Root\\File` key.

        :param programs_key: The `Root\\File` registry key.

        :return: An iterator of tuples, where the first member is the program ID string for
        correlating `Root\\Program` entries, and the second member is the `AmcacheEntry`.
        """
        try:
            data = actions_value.decode_data()
        except exceptions.InvalidAddressException:
            data = None

        if not isinstance(data, bytes):
            return None

        return ActionSet.decode(data)

    @classmethod
    def parse_triggers_value(
        cls, triggers_value: reg_extensions.CM_KEY_VALUE
    ) -> Optional[TriggerSet]:
        try:
            data = triggers_value.decode_data()
        except exceptions.InvalidAddressException:
            data = None

        if not isinstance(data, bytes):
            return None

        return TriggerSet.decode(data)

    @classmethod
    def parse_dynamic_info_value(
        cls, dyn_info_value: reg_extensions.CM_KEY_VALUE
    ) -> Optional[DynamicInfo]:

        try:
            data = dyn_info_value.decode_data()
        except exceptions.InvalidAddressException:
            data = None

        if not isinstance(data, bytes):
            return None

        return DynamicInfo.decode(data)

    @classmethod
    def _get_task_keys(
        cls, software_hive: reg_extensions.RegistryHive
    ) -> Tuple[
        Optional[reg_extensions.CM_KEY_NODE], Optional[reg_extensions.CM_KEY_NODE]
    ]:
        try:
            task_key = software_hive.get_key(
                "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"
            )
        except (KeyError, registry.RegistryFormatException):
            task_key = None

        try:
            task_tree = software_hive.get_key(
                "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree"
            )
        except (KeyError, registry.RegistryFormatException):
            task_tree = None

        return (task_key, task_tree)  # type: ignore

    @classmethod
    def _parse_task_key(
        cls, key: reg_extensions.CM_KEY_NODE, guid_mapping: Dict[str, str]
    ) -> Iterator[_ScheduledTaskEntry]:
        values = {}
        for value in key.get_values():
            try:
                name = str(value.get_name())
            except exceptions.InvalidAddressException:
                continue

            if name in ["Actions", "Triggers", "DynamicInfo"]:
                values[name] = value

        task_name = guid_mapping.get(str(key.get_name()), renderers.NotAvailableValue())

        try:
            action_set = cls.parse_actions_value(values["Actions"])
        except KeyError:
            vollog.debug("Failed to get Actions value")
            action_set = None

        try:
            triggers_value = values["Triggers"]
            trigger_set = cls.parse_triggers_value(triggers_value)
        except KeyError:
            vollog.debug("Failed to get Triggers value")
            trigger_set = None

        if trigger_set is not None:
            vollog.debug("Parsed triggers successfully")

            principal_id = (
                trigger_set.job_bucket.principal_id or renderers.NotAvailableValue()
            )
            display_name = (
                trigger_set.job_bucket.display_name or renderers.NotAvailableValue()
            )
        else:
            vollog.debug("Failed to parse triggers")

            principal_id = renderers.NotAvailableValue()
            display_name = renderers.NotAvailableValue()

        try:
            dynamic_info = cls.parse_dynamic_info_value(values["DynamicInfo"])
        except KeyError:
            vollog.debug("DynamicInfo value not found")
            dynamic_info = None

        vollog.debug(dynamic_info)

        creation_time = dynamic_info.creation_time if dynamic_info is not None else None
        last_run_time = dynamic_info.last_run_time if dynamic_info is not None else None
        last_successful_run_time = (
            dynamic_info.last_successful_run_time if dynamic_info is not None else None
        )

        all_triggers = (
            trigger_set.triggers or [None] if trigger_set is not None else [None]
        )

        all_actions = action_set.actions or [None] if action_set is not None else [None]

        for action, trigger in itertools.product(all_actions, all_triggers):

            if action is not None:
                if action.action_type in (
                    ActionType.Exe,
                    ActionType.ComHandler,
                ):
                    if action.action_args is None:
                        args = renderers.NotAvailableValue()
                    else:
                        args = action.action_args
                else:
                    args = renderers.NotApplicableValue()

                if action.action_type == ActionType.Exe:
                    working_directory = (
                        action.working_directory or renderers.NotAvailableValue()
                    )
                else:
                    working_directory = renderers.NotApplicableValue()

            else:
                args = renderers.NotAvailableValue()
                working_directory = renderers.NotAvailableValue()

            if trigger is not None and trigger.enabled is not None:
                enabled = trigger.enabled
            else:
                enabled = renderers.NotAvailableValue()

            yield _ScheduledTaskEntry(
                task_name,
                principal_id,
                display_name,
                enabled,
                creation_time or renderers.NotAvailableValue(),
                last_run_time or renderers.NotAvailableValue(),
                last_successful_run_time or renderers.NotAvailableValue(),
                (
                    trigger.trigger_type.name
                    if trigger is not None
                    else renderers.NotAvailableValue()
                ),
                (
                    trigger.description or renderers.NotAvailableValue()
                    if trigger is not None
                    else renderers.NotAvailableValue()
                ),
                (
                    action.action_type.name
                    if action is not None
                    else renderers.NotAvailableValue()
                ),
                (
                    action.action
                    if action is not None
                    else renderers.NotAvailableValue()
                ),
                args,
                (
                    action_set.context
                    if action_set is not None
                    else renderers.NotAvailableValue()
                ),
                working_directory,
                str(key.get_name()),
            )

    def _generator(self) -> Iterator[Tuple[int, _ScheduledTaskEntry]]:
        kernel = self.context.modules[self.config["kernel"]]

        # Building the dictionary ahead of time is much better for performance
        # vs looking up each service's DLL individually.
        software_hive = self.get_software_hive(self.context, self.config_path, kernel)
        if software_hive is None:
            vollog.warning("Failed to get SOFTWARE hive")
            return

        task_key_root, task_tree = self._get_task_keys(software_hive)
        if task_key_root is None:
            vollog.warning("Failed to get 'Tasks' key")
            return

        if task_tree is not None:
            task_name_map = _build_guid_name_map(task_tree)
        else:
            vollog.info("'Tree' key not found, can't map GUIDs to task names")
            task_name_map = {}

        for key in task_key_root.get_subkeys():
            for task in self._parse_task_key(key, task_name_map):
                yield 0, task

    def run(self):
        return renderers.TreeGrid(
            [
                ("Task Name", str),
                ("Principal ID", str),
                ("Display Name", str),
                ("Enabled", bool),
                ("Creation Time", datetime.datetime),
                ("Last Run Time", datetime.datetime),
                ("Last Successful Run Time", datetime.datetime),
                ("Trigger Type", str),
                ("Trigger Description", str),
                ("Action Type", str),
                ("Action", str),
                ("Action Arguments", str),
                ("Action Context", str),
                ("Working Directory", str),
                ("Key Name", str),
            ],
            (
                (indent, dataclasses.astuple(entry))
                for indent, entry in self._generator()
            ),
        )


class TestActionsDecoding(unittest.TestCase):
    def test_decode_exe_action(self):
        # fmt: off
        buf = struct.pack(
            "512B",
            *[
                0x03, 0x00, 0x16, 0x00, 0x00, 0x00, 0x4c, 0x00,
                0x6f, 0x00, 0x63, 0x00, 0x61, 0x00, 0x6c, 0x00,
                0x53, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00,
                0x65, 0x00, 0x6d, 0x00, 0x66, 0x66, 0x00, 0x00,
                0x00, 0x00, 0x6e, 0x00, 0x00, 0x00, 0x25, 0x00,
                0x77, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x64, 0x00,
                0x69, 0x00, 0x72, 0x00, 0x25, 0x00, 0x5c, 0x00,
                0x73, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00,
                0x65, 0x00, 0x6d, 0x00, 0x33, 0x00, 0x32, 0x00,
                0x5c, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6e, 0x00,
                0x64, 0x00, 0x6f, 0x00, 0x77, 0x00, 0x73, 0x00,
                0x50, 0x00, 0x6f, 0x00, 0x77, 0x00, 0x65, 0x00,
                0x72, 0x00, 0x53, 0x00, 0x68, 0x00, 0x65, 0x00,
                0x6c, 0x00, 0x6c, 0x00, 0x5c, 0x00, 0x76, 0x00,
                0x31, 0x00, 0x2e, 0x00, 0x30, 0x00, 0x5c, 0x00,
                0x70, 0x00, 0x6f, 0x00, 0x77, 0x00, 0x65, 0x00,
                0x72, 0x00, 0x73, 0x00, 0x68, 0x00, 0x65, 0x00,
                0x6c, 0x00, 0x6c, 0x00, 0x2e, 0x00, 0x65, 0x00,
                0x78, 0x00, 0x65, 0x00, 0x62, 0x01, 0x00, 0x00,
                0x2d, 0x00, 0x45, 0x00, 0x78, 0x00, 0x65, 0x00,
                0x63, 0x00, 0x75, 0x00, 0x74, 0x00, 0x69, 0x00,
                0x6f, 0x00, 0x6e, 0x00, 0x50, 0x00, 0x6f, 0x00,
                0x6c, 0x00, 0x69, 0x00, 0x63, 0x00, 0x79, 0x00,
                0x20, 0x00, 0x55, 0x00, 0x6e, 0x00, 0x72, 0x00,
                0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x72, 0x00,
                0x69, 0x00, 0x63, 0x00, 0x74, 0x00, 0x65, 0x00,
                0x64, 0x00, 0x20, 0x00, 0x2d, 0x00, 0x4e, 0x00,
                0x6f, 0x00, 0x6e, 0x00, 0x49, 0x00, 0x6e, 0x00,
                0x74, 0x00, 0x65, 0x00, 0x72, 0x00, 0x61, 0x00,
                0x63, 0x00, 0x74, 0x00, 0x69, 0x00, 0x76, 0x00,
                0x65, 0x00, 0x20, 0x00, 0x2d, 0x00, 0x4e, 0x00,
                0x6f, 0x00, 0x50, 0x00, 0x72, 0x00, 0x6f, 0x00,
                0x66, 0x00, 0x69, 0x00, 0x6c, 0x00, 0x65, 0x00,
                0x20, 0x00, 0x2d, 0x00, 0x57, 0x00, 0x69, 0x00,
                0x6e, 0x00, 0x64, 0x00, 0x6f, 0x00, 0x77, 0x00,
                0x53, 0x00, 0x74, 0x00, 0x79, 0x00, 0x6c, 0x00,
                0x65, 0x00, 0x20, 0x00, 0x48, 0x00, 0x69, 0x00,
                0x64, 0x00, 0x64, 0x00, 0x65, 0x00, 0x6e, 0x00,
                0x20, 0x00, 0x22, 0x00, 0x26, 0x00, 0x20, 0x00,
                0x25, 0x00, 0x77, 0x00, 0x69, 0x00, 0x6e, 0x00,
                0x64, 0x00, 0x69, 0x00, 0x72, 0x00, 0x25, 0x00,
                0x5c, 0x00, 0x73, 0x00, 0x79, 0x00, 0x73, 0x00,
                0x74, 0x00, 0x65, 0x00, 0x6d, 0x00, 0x33, 0x00,
                0x32, 0x00, 0x5c, 0x00, 0x57, 0x00, 0x69, 0x00,
                0x6e, 0x00, 0x64, 0x00, 0x6f, 0x00, 0x77, 0x00,
                0x73, 0x00, 0x50, 0x00, 0x6f, 0x00, 0x77, 0x00,
                0x65, 0x00, 0x72, 0x00, 0x53, 0x00, 0x68, 0x00,
                0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x5c, 0x00,
                0x76, 0x00, 0x31, 0x00, 0x2e, 0x00, 0x30, 0x00,
                0x5c, 0x00, 0x4d, 0x00, 0x6f, 0x00, 0x64, 0x00,
                0x75, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x73, 0x00,
                0x5c, 0x00, 0x53, 0x00, 0x6d, 0x00, 0x62, 0x00,
                0x53, 0x00, 0x68, 0x00, 0x61, 0x00, 0x72, 0x00,
                0x65, 0x00, 0x5c, 0x00, 0x44, 0x00, 0x69, 0x00,
                0x73, 0x00, 0x61, 0x00, 0x62, 0x00, 0x6c, 0x00,
                0x65, 0x00, 0x55, 0x00, 0x6e, 0x00, 0x75, 0x00,
                0x73, 0x00, 0x65, 0x00, 0x64, 0x00, 0x53, 0x00,
                0x6d, 0x00, 0x62, 0x00, 0x31, 0x00, 0x2e, 0x00,
                0x70, 0x00, 0x73, 0x00, 0x31, 0x00, 0x20, 0x00,
                0x2d, 0x00, 0x53, 0x00, 0x63, 0x00, 0x65, 0x00,
                0x6e, 0x00, 0x61, 0x00, 0x72, 0x00, 0x69, 0x00,
                0x6f, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6c, 0x00,
                0x69, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x74, 0x00,
                0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        )

        try:
            actions = ActionSet.decode(buf)  # type: ignore
            self.assertEqual(len(actions), 1)
            self.assertEqual(actions[0].action_type, ActionType.Exe)
        except Exception:
            self.fail(
                "ActionDecoder.decode should not raise exception:\n%s"
                % traceback.format_exc()
            )


class TestTriggersDecoding(unittest.TestCase):
    def test_decode_all_triggers(self):
        """
        Tests decoding a set of all triggers that can be constructed via the
        Task Scheduler GUI interface. Ensures that the correct number of bytes
        is being consumed for each trigger structure.
        """
        buf = struct.pack(
            "1808B",
            # fmt: off
            *[
                0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xda, 0xaf, 0x8d, 0x09, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xda, 0xaf, 0x8d, 0x09, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x38, 0x21, 0x41, 0x42, 0x48, 0x48, 0x48, 0x48,
                0xa0, 0x12, 0xa0, 0xa4, 0x48, 0x48, 0x48, 0x48,
                0x0e, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x41, 0x00, 0x75, 0x00, 0x74, 0x00, 0x68, 0x00,
                0x6f, 0x00, 0x72, 0x00, 0x00, 0x00, 0x48, 0x48,
                0x00, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x00, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
                0x00, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
                0x01, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x1c, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
                0x15, 0x00, 0x00, 0x00, 0x69, 0xce, 0x28, 0x2a,
                0xce, 0xd8, 0x1f, 0x77, 0x37, 0x9c, 0xe2, 0x44,
                0xf4, 0x01, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x40, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x44, 0x00, 0x45, 0x00, 0x53, 0x00, 0x4b, 0x00,
                0x54, 0x00, 0x4f, 0x00, 0x50, 0x00, 0x2d, 0x00,
                0x45, 0x00, 0x33, 0x00, 0x38, 0x00, 0x38, 0x00,
                0x44, 0x00, 0x38, 0x00, 0x50, 0x00, 0x5c, 0x00,
                0x41, 0x00, 0x64, 0x00, 0x6d, 0x00, 0x69, 0x00,
                0x6e, 0x00, 0x69, 0x00, 0x73, 0x00, 0x74, 0x00,
                0x72, 0x00, 0x61, 0x00, 0x74, 0x00, 0x6f, 0x00,
                0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x2c, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
                0x80, 0xf4, 0x03, 0x00, 0xff, 0xff, 0xff, 0xff,
                0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0xdd, 0xdd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x07, 0x0a, 0x00, 0x00, 0x00, 0x09, 0x00,
                0x80, 0x48, 0x11, 0xf8, 0x36, 0x1a, 0xdb, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01, 0x2e, 0xe2, 0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0xc2, 0x31, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xda, 0xaf, 0x8d, 0x09, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xda, 0xaf, 0x8d, 0x09, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x01, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
                0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xda, 0xaf, 0x8d, 0x09, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xda, 0xaf, 0x8d, 0x09, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0xee, 0xee, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xda, 0xaf, 0x8d, 0x09, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xda, 0xaf, 0x8d, 0x09, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0xcc, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x65, 0x00, 0x78, 0x00, 0x65, 0x00,
                0x22, 0x00, 0x20, 0x00, 0x53, 0x00, 0x74, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x3c, 0x00, 0x51, 0x00, 0x75, 0x00, 0x65, 0x00,
                0x72, 0x00, 0x79, 0x00, 0x4c, 0x00, 0x69, 0x00,
                0x73, 0x00, 0x74, 0x00, 0x3e, 0x00, 0x3c, 0x00,
                0x51, 0x00, 0x75, 0x00, 0x65, 0x00, 0x72, 0x00,
                0x79, 0x00, 0x20, 0x00, 0x49, 0x00, 0x64, 0x00,
                0x3d, 0x00, 0x22, 0x00, 0x30, 0x00, 0x22, 0x00,
                0x20, 0x00, 0x50, 0x00, 0x61, 0x00, 0x74, 0x00,
                0x68, 0x00, 0x3d, 0x00, 0x22, 0x00, 0x49, 0x00,
                0x6e, 0x00, 0x74, 0x00, 0x65, 0x00, 0x72, 0x00,
                0x6e, 0x00, 0x65, 0x00, 0x74, 0x00, 0x20, 0x00,
                0x45, 0x00, 0x78, 0x00, 0x70, 0x00, 0x6c, 0x00,
                0x6f, 0x00, 0x72, 0x00, 0x65, 0x00, 0x72, 0x00,
                0x22, 0x00, 0x3e, 0x00, 0x3c, 0x00, 0x53, 0x00,
                0x65, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x63, 0x00,
                0x74, 0x00, 0x20, 0x00, 0x50, 0x00, 0x61, 0x00,
                0x74, 0x00, 0x68, 0x00, 0x3d, 0x00, 0x22, 0x00,
                0x49, 0x00, 0x6e, 0x00, 0x74, 0x00, 0x65, 0x00,
                0x72, 0x00, 0x6e, 0x00, 0x65, 0x00, 0x74, 0x00,
                0x20, 0x00, 0x45, 0x00, 0x78, 0x00, 0x70, 0x00,
                0x6c, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x65, 0x00,
                0x72, 0x00, 0x22, 0x00, 0x3e, 0x00, 0x2a, 0x00,
                0x5b, 0x00, 0x53, 0x00, 0x79, 0x00, 0x73, 0x00,
                0x74, 0x00, 0x65, 0x00, 0x6d, 0x00, 0x5b, 0x00,
                0x45, 0x00, 0x76, 0x00, 0x65, 0x00, 0x6e, 0x00,
                0x74, 0x00, 0x49, 0x00, 0x44, 0x00, 0x3d, 0x00,
                0x32, 0x00, 0x5d, 0x00, 0x5d, 0x00, 0x3c, 0x00,
                0x2f, 0x00, 0x53, 0x00, 0x65, 0x00, 0x6c, 0x00,
                0x65, 0x00, 0x63, 0x00, 0x74, 0x00, 0x3e, 0x00,
                0x3c, 0x00, 0x2f, 0x00, 0x51, 0x00, 0x75, 0x00,
                0x65, 0x00, 0x72, 0x00, 0x79, 0x00, 0x3e, 0x00,
                0x3c, 0x00, 0x2f, 0x00, 0x51, 0x00, 0x75, 0x00,
                0x65, 0x00, 0x72, 0x00, 0x79, 0x00, 0x4c, 0x00,
                0x69, 0x00, 0x73, 0x00, 0x74, 0x00, 0x3e, 0x00,
                0x00, 0x00, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x88, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x77, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x01, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
                0x77, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
                0x00, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
                0x01, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x1c, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
                0x15, 0x00, 0x00, 0x00, 0x69, 0xce, 0x28, 0x2a,
                0xce, 0xd8, 0x1f, 0x77, 0x37, 0x9c, 0xe2, 0x44,
                0xf4, 0x01, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x40, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x44, 0x00, 0x45, 0x00, 0x53, 0x00, 0x4b, 0x00,
                0x54, 0x00, 0x4f, 0x00, 0x50, 0x00, 0x2d, 0x00,
                0x45, 0x00, 0x33, 0x00, 0x38, 0x00, 0x38, 0x00,
                0x44, 0x00, 0x38, 0x00, 0x50, 0x00, 0x5c, 0x00,
                0x41, 0x00, 0x64, 0x00, 0x6d, 0x00, 0x69, 0x00,
                0x6e, 0x00, 0x69, 0x00, 0x73, 0x00, 0x74, 0x00,
                0x72, 0x00, 0x61, 0x00, 0x74, 0x00, 0x6f, 0x00,
                0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x77, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x01, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
                0x77, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x01, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
                0x00, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
                0x01, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x1c, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
                0x15, 0x00, 0x00, 0x00, 0x69, 0xce, 0x28, 0x2a,
                0xce, 0xd8, 0x1f, 0x77, 0x37, 0x9c, 0xe2, 0x44,
                0xf4, 0x01, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x40, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x44, 0x00, 0x45, 0x00, 0x53, 0x00, 0x4b, 0x00,
                0x54, 0x00, 0x4f, 0x00, 0x50, 0x00, 0x2d, 0x00,
                0x45, 0x00, 0x33, 0x00, 0x38, 0x00, 0x38, 0x00,
                0x44, 0x00, 0x38, 0x00, 0x50, 0x00, 0x5c, 0x00,
                0x41, 0x00, 0x64, 0x00, 0x6d, 0x00, 0x69, 0x00,
                0x6e, 0x00, 0x69, 0x00, 0x73, 0x00, 0x74, 0x00,
                0x72, 0x00, 0x61, 0x00, 0x74, 0x00, 0x6f, 0x00,
                0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
            # fmt: on
        )
        triggers = TriggerSet.decode(buf)
        self.assertIsNotNone(triggers)

    def test_decode_triggers(self):
        # fmt: off
        buf = struct.pack(
            "320B",
            *[
                0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xB9, 0x61, 0x1A, 0xA8, 0xB9, 0x61, 0x1A,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xB9, 0x61, 0x1A, 0xA8, 0xB9, 0x61, 0x1A,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0x08, 0xA1, 0x40, 0x42, 0x48, 0x48, 0x48, 0x48,
                0x7A, 0x7F, 0x59, 0xDC, 0x48, 0x48, 0x48, 0x48,
                0x22, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x49, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x65, 0x00,
                0x72, 0x00, 0x61, 0x00, 0x63, 0x00, 0x74, 0x00,
                0x69, 0x00, 0x76, 0x00, 0x65, 0x00, 0x55, 0x00,
                0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00,
                0x00, 0x00, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
                0x00, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x00, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
                0x00, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
                0x05, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x0C, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
                0x04, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x00, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x2C, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                0x80, 0x51, 0x01, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xB9, 0x61, 0x1A, 0xA8, 0xB9, 0x61, 0x1A,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xB9, 0x61, 0x1A, 0xA8, 0xB9, 0x61, 0x1A,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0x2C, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0xC1, 0xD9, 0x04,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x48, 0x48, 0x48, 0x48,
                0x01, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
            ]
        )
        # fmt: on
        triggers = TriggerSet.decode(buf)
        self.assertIsNotNone(triggers)
        if not triggers:
            return
        self.assertGreater(len(triggers.triggers), 0)
