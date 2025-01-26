# volatility3 tests
#

#
# IMPORTS
#

import os
import re
import subprocess
import sys
import shutil
import tempfile
import hashlib
import ntpath
import json
import contextlib

#
# HELPER FUNCTIONS
#


def runvol(args, volatility, python):
    volpy = volatility
    python_cmd = python

    cmd = [python_cmd, volpy] + args
    print(" ".join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    print("stdout:")
    sys.stdout.write(str(stdout))
    print("")
    print("stderr:")
    sys.stdout.write(str(stderr))
    print("")

    return p.returncode, stdout, stderr


def runvol_plugin(plugin, img, volatility, python, pluginargs=None, globalargs=None):
    pluginargs = pluginargs or []
    globalargs = globalargs or []
    args = (
        globalargs
        + [
            "--single-location",
            img,
            "-q",
            plugin,
        ]
        + pluginargs
    )

    return runvol(args, volatility, python)


def runvolshell(img, volshell, python, volshellargs=None, globalargs=None):
    volshellargs = volshellargs or []
    globalargs = globalargs or []
    args = (
        globalargs
        + [
            "--single-location",
            img,
            "-q",
        ]
        + volshellargs
    )

    return runvol(args, volshell, python)


#
# TESTS
#


def basic_volshell_test(image, volatility, python, globalargs):
    # Basic VolShell test to verify requirements and ensure VolShell runs without crashing

    volshell_commands = [
        "print(ps())",
        "exit()",
    ]

    # FIXME: When the minimum Python version includes 3.12, replace the following with:
    # with tempfile.NamedTemporaryFile(delete_on_close=False) as fd: ...
    fd, filename = tempfile.mkstemp(suffix=".txt")
    try:
        volshell_script = "\n".join(volshell_commands)
        with os.fdopen(fd, "w") as f:
            f.write(volshell_script)

        rc, out, _err = runvolshell(
            img=image,
            volshell=volatility,
            python=python,
            volshellargs=["--script", filename],
            globalargs=globalargs,
        )
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.remove(filename)

    assert rc == 0
    assert out.count(b"\n") >= 4

    return out


# WINDOWS


def test_windows_volshell(image, volatility, python):
    out = basic_volshell_test(image, volatility, python, globalargs=["-w"])
    assert out.count(b"<EPROCESS") > 40


def test_windows_pslist(image, volatility, python):
    rc, out, _err = runvol_plugin("windows.pslist.PsList", image, volatility, python)
    out = out.lower()
    assert out.find(b"system") != -1
    assert out.find(b"csrss.exe") != -1
    assert out.find(b"svchost.exe") != -1
    assert out.count(b"\n") > 10
    assert rc == 0

    rc, out, _err = runvol_plugin(
        "windows.pslist.PsList", image, volatility, python, pluginargs=["--pid", "4"]
    )
    out = out.lower()
    assert out.find(b"system") != -1
    assert out.count(b"\n") < 10
    assert rc == 0


def test_windows_psscan(image, volatility, python):
    rc, out, _err = runvol_plugin("windows.psscan.PsScan", image, volatility, python)
    out = out.lower()
    assert out.find(b"system") != -1
    assert out.find(b"csrss.exe") != -1
    assert out.find(b"svchost.exe") != -1
    assert out.count(b"\n") > 10
    assert rc == 0


def test_windows_dlllist(image, volatility, python):
    rc, out, _err = runvol_plugin("windows.dlllist.DllList", image, volatility, python)
    out = out.lower()
    assert out.count(b"\n") > 10
    assert rc == 0


def test_windows_modules(image, volatility, python):
    rc, out, _err = runvol_plugin("windows.modules.Modules", image, volatility, python)
    out = out.lower()
    assert out.count(b"\n") > 10
    assert rc == 0


def test_windows_hivelist(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "windows.registry.hivelist.HiveList", image, volatility, python
    )
    out = out.lower()

    not_xp = out.find(b"\\systemroot\\system32\\config\\software")
    if not_xp == -1:
        assert (
            out.find(b"\\device\\harddiskvolume1\\windows\\system32\\config\\software")
            != -1
        )

    assert out.count(b"\n") > 10
    assert rc == 0


def test_windows_dumpfiles(image, volatility, python):

    with open("./test/known_files.json") as json_file:
        known_files = json.load(json_file)

    failed_chksms = 0

    if sys.platform == "win32":
        file_name = ntpath.basename(image)
    else:
        file_name = os.path.basename(image)

    try:
        for addr in known_files["windows_dumpfiles"][file_name]:

            path = tempfile.mkdtemp()

            rc, _out, _err = runvol_plugin(
                "windows.dumpfiles.DumpFiles",
                image,
                volatility,
                python,
                globalargs=["-o", path],
                pluginargs=["--virtaddr", addr],
            )

            for file in os.listdir(path):
                with open(os.path.join(path, file), "rb") as fp:
                    if (
                        hashlib.md5(fp.read()).hexdigest()
                        not in known_files["windows_dumpfiles"][file_name][addr]
                    ):
                        failed_chksms += 1

            shutil.rmtree(path)

        json_file.close()

        assert failed_chksms == 0
        assert rc == 0
    except Exception as e:
        json_file.close()
        print("Key Error raised on " + str(e))
        assert False


def test_windows_handles(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "windows.handles.Handles", image, volatility, python, pluginargs=["--pid", "4"]
    )

    assert out.find(b"System Pid 4") != -1
    assert (
        out.find(
            b"MACHINE\\SYSTEM\\CONTROLSET001\\CONTROL\\SESSION MANAGER\\MEMORY MANAGEMENT\\PREFETCHPARAMETERS"
        )
        != -1
    )
    assert out.find(b"MACHINE\\SYSTEM\\SETUP") != -1
    assert out.count(b"\n") > 500
    assert rc == 0


def test_windows_svcscan(image, volatility, python):
    rc, out, _err = runvol_plugin("windows.svcscan.SvcScan", image, volatility, python)

    assert out.find(b"Microsoft ACPI Driver") != -1
    assert out.count(b"\n") > 250
    assert rc == 0


def test_windows_thrdscan(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "windows.thrdscan.ThrdScan", image, volatility, python
    )
    # find pid 4 (of system process) which starts with lowest tids
    assert out.find(b"\t4\t8") != -1
    assert out.find(b"\t4\t12") != -1
    assert out.find(b"\t4\t16") != -1
    # assert out.find(b"this raieses AssertionError") != -1
    assert rc == 0


def test_windows_privileges(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "windows.privileges.Privs", image, volatility, python, pluginargs=["--pid", "4"]
    )

    assert out.find(b"SeCreateTokenPrivilege") != -1
    assert out.find(b"SeCreateGlobalPrivilege") != -1
    assert out.find(b"SeAssignPrimaryTokenPrivilege") != -1
    assert out.count(b"\n") > 20
    assert rc == 0


def test_windows_getsids(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "windows.getsids.GetSIDs", image, volatility, python, pluginargs=["--pid", "4"]
    )

    assert out.find(b"Local System") != -1
    assert out.find(b"Administrators") != -1
    assert out.find(b"Everyone") != -1
    assert out.find(b"Authenticated Users") != -1
    assert rc == 0


def test_windows_envars(image, volatility, python):
    rc, out, _err = runvol_plugin("windows.envars.Envars", image, volatility, python)

    assert out.find(b"PATH") != -1
    assert out.find(b"PROCESSOR_ARCHITECTURE") != -1
    assert out.find(b"USERNAME") != -1
    assert out.find(b"SystemRoot") != -1
    assert out.find(b"CommonProgramFiles") != -1
    assert out.count(b"\n") > 500
    assert rc == 0


def test_windows_callbacks(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "windows.callbacks.Callbacks", image, volatility, python
    )

    assert out.find(b"PspCreateProcessNotifyRoutine") != -1
    assert out.find(b"KeBugCheckCallbackListHead") != -1
    assert out.find(b"KeBugCheckReasonCallbackListHead") != -1
    assert out.count(b"KeBugCheckReasonCallbackListHead	") > 5
    assert rc == 0


def test_windows_vadwalk(image, volatility, python):
    rc, out, _err = runvol_plugin("windows.vadwalk.VadWalk", image, volatility, python)

    assert out.find(b"Vad") != -1
    assert out.find(b"VadS") != -1
    assert out.find(b"Vadl") != -1
    assert out.find(b"VadF") != -1
    assert out.find(b"0x0") != -1
    assert rc == 0


def test_windows_devicetree(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "windows.devicetree.DeviceTree", image, volatility, python
    )

    assert out.find(b"DEV") != -1
    assert out.find(b"DRV") != -1
    assert out.find(b"ATT") != -1
    assert out.find(b"FILE_DEVICE_CONTROLLER") != -1
    assert out.find(b"FILE_DEVICE_DISK") != -1
    assert out.find(b"FILE_DEVICE_DISK_FILE_SYSTEM") != -1
    assert rc == 0


def test_windows_vadyarascan_yara_rule(image, volatility, python):
    yara_rule_01 = r"""
        rule fullvadyarascan
        {
            strings:
                $s1 = "!This program cannot be run in DOS mode."
                $s2 = "Qw))Pw"
                $s3 = "W_wD)Pw"
                $s4 = "1Xw+2Xw"
                $s5 = "xd`wh``w"
                $s6 = "0g`w0g`w8g`w8g`w@g`w@g`wHg`wHg`wPg`wPg`wXg`wXg`w`g`w`g`whg`whg`wpg`wpg`wxg`wxg`w"
            condition:
                all of them
        }
    """

    # FIXME: When the minimum Python version includes 3.12, replace the following with:
    # with tempfile.NamedTemporaryFile(delete_on_close=False) as fd: ...
    fd, filename = tempfile.mkstemp(suffix=".yar")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(yara_rule_01)

        rc, out, _err = runvol_plugin(
            "windows.vadyarascan.VadYaraScan",
            image,
            volatility,
            python,
            pluginargs=["--pid", "4012", "--yara-file", filename],
        )
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.remove(filename)

    out = out.lower()
    assert out.count(b"\n") > 4
    assert rc == 0


def test_windows_vadyarascan_yara_string(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "windows.vadyarascan.VadYaraScan",
        image,
        volatility,
        python,
        pluginargs=["--pid", "4012", "--yara-string", "MZ"],
    )
    out = out.lower()

    assert out.count(b"\n") > 10
    assert rc == 0


# LINUX


def test_linux_volshell(image, volatility, python):
    out = basic_volshell_test(image, volatility, python, globalargs=["-l"])
    assert out.count(b"<task_struct") > 100


def test_linux_pslist(image, volatility, python):
    rc, out, _err = runvol_plugin("linux.pslist.PsList", image, volatility, python)

    assert rc == 0
    out = out.lower()
    assert (out.find(b"init") != -1) or (out.find(b"systemd") != -1)
    assert out.find(b"watchdog") != -1
    assert out.count(b"\n") > 10


def test_linux_check_idt(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "linux.check_idt.Check_idt", image, volatility, python
    )

    assert rc == 0
    out = out.lower()
    assert out.count(b"__kernel__") >= 10
    assert out.count(b"\n") > 10


def test_linux_check_syscall(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "linux.check_syscall.Check_syscall", image, volatility, python
    )

    assert rc == 0
    out = out.lower()
    assert out.find(b"sys_close") != -1
    assert out.find(b"sys_open") != -1
    assert out.count(b"\n") > 100


def test_linux_lsmod(image, volatility, python):
    rc, out, _err = runvol_plugin("linux.lsmod.Lsmod", image, volatility, python)

    assert rc == 0
    out = out.lower()
    assert out.count(b"\n") > 10


def test_linux_lsof(image, volatility, python):
    rc, out, _err = runvol_plugin("linux.lsof.Lsof", image, volatility, python)

    assert rc == 0
    out = out.lower()
    assert out.count(b"socket:") >= 10
    assert out.count(b"\n") > 35


def test_linux_proc_maps(image, volatility, python):
    rc, out, _err = runvol_plugin("linux.proc.Maps", image, volatility, python)

    assert rc == 0
    out = out.lower()
    assert out.count(b"anonymous mapping") >= 10
    assert out.count(b"\n") > 100


def test_linux_tty_check(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "linux.tty_check.tty_check", image, volatility, python
    )

    assert rc == 0
    out = out.lower()
    assert out.find(b"__kernel__") != -1
    assert out.count(b"\n") >= 5


def test_linux_sockstat(image, volatility, python):
    rc, out, _err = runvol_plugin("linux.sockstat.Sockstat", image, volatility, python)

    assert rc == 0
    assert out.count(b"AF_UNIX") >= 354
    assert out.count(b"AF_BLUETOOTH") >= 5
    assert out.count(b"AF_INET") >= 32
    assert out.count(b"AF_INET6") >= 20
    assert out.count(b"AF_PACKET") >= 1
    assert out.count(b"AF_NETLINK") >= 43


def test_linux_library_list(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "linux.library_list.LibraryList",
        image,
        volatility,
        python,
        pluginargs=["--pids", "2363"],
    )

    assert rc == 0
    assert re.search(
        rb"NetworkManager\s2363\s0x7f52cdda0000\s/lib/x86_64-linux-gnu/libnss_files.so.2",
        out,
    )

    assert out.count(b"\n") > 10


def test_linux_pstree(image, volatility, python):
    rc, out, _err = runvol_plugin("linux.pstree.PsTree", image, volatility, python)

    assert rc == 0
    out = out.lower()
    assert (out.find(b"init") != -1) or (out.find(b"systemd") != -1)
    assert out.count(b"\n") > 10


def test_linux_pidhashtable(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "linux.pidhashtable.PIDHashTable", image, volatility, python
    )

    assert rc == 0
    out = out.lower()
    assert (out.find(b"init") != -1) or (out.find(b"systemd") != -1)
    assert out.count(b"\n") > 10


def test_linux_bash(image, volatility, python):
    rc, out, _err = runvol_plugin("linux.bash.Bash", image, volatility, python)

    assert rc == 0
    assert out.count(b"\n") > 10


def test_linux_boottime(image, volatility, python):
    rc, out, _err = runvol_plugin("linux.boottime.Boottime", image, volatility, python)

    assert rc == 0
    out = out.lower()
    assert out.count(b"utc") >= 1


def test_linux_capabilities(image, volatility, python):
    rc, out, err = runvol_plugin(
        "linux.capabilities.Capabilities",
        image,
        volatility,
        python,
        globalargs=["-vvv"],
    )

    if rc != 0 and err.count(b"Unsupported kernel capabilities implementation") > 0:
        # The linux-sample-1.bin kernel implementation isn't supported.
        # However, we can still check that the plugin requirements are met.
        return None

    assert rc == 0
    assert out.count(b"\n") > 10


def test_linux_check_creds(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "linux.check_creds.Check_creds", image, volatility, python
    )

    # linux-sample-1.bin has no processes sharing credentials.
    # This validates that plugin requirements are met and exceptions are not raised.
    assert rc == 0
    assert out.count(b"\n") >= 4


def test_linux_elfs(image, volatility, python):
    rc, out, _err = runvol_plugin("linux.elfs.Elfs", image, volatility, python)

    assert rc == 0
    assert out.count(b"\n") > 10


def test_linux_envars(image, volatility, python):
    rc, out, _err = runvol_plugin("linux.envars.Envars", image, volatility, python)

    assert rc == 0
    assert out.count(b"\n") > 10


def test_linux_kthreads(image, volatility, python):
    rc, out, err = runvol_plugin(
        "linux.kthreads.Kthreads",
        image,
        volatility,
        python,
        globalargs=["-vvv"],
    )

    if rc != 0 and err.count(b"Unsupported kthread implementation") > 0:
        # The linux-sample-1.bin kernel implementation isn't supported.
        # However, we can still check that the plugin requirements are met.
        return None

    assert rc == 0
    assert out.count(b"\n") >= 4


def test_linux_malfind(image, volatility, python):
    rc, out, _err = runvol_plugin("linux.malfind.Malfind", image, volatility, python)

    # linux-sample-1.bin has no process memory ranges with potential injected code.
    # This validates that plugin requirements are met and exceptions are not raised.
    assert rc == 0
    assert out.count(b"\n") >= 4


def test_linux_mountinfo(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "linux.mountinfo.MountInfo", image, volatility, python
    )

    assert rc == 0
    assert out.count(b"\n") > 10


def test_linux_psaux(image, volatility, python):
    rc, out, _err = runvol_plugin("linux.psaux.PsAux", image, volatility, python)

    assert rc == 0
    assert out.count(b"\n") > 50


def test_linux_ptrace(image, volatility, python):
    rc, out, _err = runvol_plugin("linux.ptrace.Ptrace", image, volatility, python)

    # linux-sample-1.bin has no processes being ptraced.
    # This validates that plugin requirements are met and exceptions are not raised.
    assert rc == 0
    assert out.count(b"\n") >= 4


def test_linux_vmaregexscan(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "linux.vmaregexscan.VmaRegExScan",
        image,
        volatility,
        python,
        pluginargs=["--pid", "1", "--pattern", "\\x7fELF"],
    )

    assert rc == 0
    assert out.count(b"\n") > 10


def test_linux_vmayarascan_yara_rule(image, volatility, python):
    yara_rule_01 = r"""
        rule fullvmayarascan
        {
            strings:
                $s1 = "_nss_files_parse_grent"
                $s2 = "/lib64/ld-linux-x86-64.so.2"
                $s3 = "(bufferend - (char *) 0) % sizeof (char *) == 0"
            condition:
                all of them
        }
    """

    # FIXME: When the minimum Python version includes 3.12, replace the following with:
    # with tempfile.NamedTemporaryFile(delete_on_close=False) as fd: ...
    fd, filename = tempfile.mkstemp(suffix=".yar")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(yara_rule_01)

        rc, out, _err = runvol_plugin(
            "linux.vmayarascan.VmaYaraScan",
            image,
            volatility,
            python,
            pluginargs=["--pid", "8600", "--yara-file", filename],
        )
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.remove(filename)

    assert rc == 0
    assert out.count(b"\n") > 4


def test_linux_vmayarascan_yara_string(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "linux.vmayarascan.VmaYaraScan",
        image,
        volatility,
        python,
        pluginargs=["--pid", "1", "--yara-string", "ELF"],
    )

    assert rc == 0
    assert out.count(b"\n") > 10


def test_linux_page_cache_files(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "linux.pagecache.Files",
        image,
        volatility,
        python,
        pluginargs=["--find", "/etc/passwd"],
    )

    assert rc == 0
    assert out.count(b"\n") > 4

    # inode_num inode_addr ... file_path
    assert re.search(
        rb"146829\s0x88001ab5c270.*?/etc/passwd",
        out,
    )


def test_linux_page_cache_inodepages(image, volatility, python):

    inode_address = hex(0x88001AB5C270)
    inode_dump_filename = f"inode_{inode_address}.dmp"

    rc, out, _err = runvol_plugin(
        "linux.pagecache.InodePages",
        image,
        volatility,
        python,
        pluginargs=["--inode", inode_address],
    )

    assert rc == 0
    assert out.count(b"\n") > 4

    # PageVAddr PagePAddr MappingAddr .. DumpSafe
    assert re.search(
        rb"0xea000054c5f8\s0x18389000\s0x88001ab5c3b0.*?True",
        out,
    )

    try:
        rc, out, _err = runvol_plugin(
            "linux.pagecache.InodePages",
            image,
            volatility,
            python,
            pluginargs=["--inode", inode_address, "--dump"],
        )

        assert rc == 0
        assert out.count(b"\n") >= 4

        assert os.path.exists(inode_dump_filename)
        with open(inode_dump_filename, "rb") as fp:
            inode_contents = fp.read()
        assert inode_contents.count(b"\n") > 30
        assert inode_contents.count(b"root:x:0:0:root:/root:/bin/bash") > 0
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.remove(inode_dump_filename)


def test_linux_check_afinfo(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "linux.check_afinfo.Check_afinfo", image, volatility, python
    )

    # linux-sample-1.bin has no suspicious results.
    # This validates that plugin requirements are met and exceptions are not raised.
    assert rc == 0
    assert out.count(b"\n") >= 4


def test_linux_check_modules(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "linux.check_modules.Check_modules", image, volatility, python
    )

    # linux-sample-1.bin has no suspicious results.
    # This validates that plugin requirements are met and exceptions are not raised.
    assert rc == 0
    assert out.count(b"\n") >= 4


def test_linux_ebpf_progs(image, volatility, python):
    rc, out, err = runvol_plugin(
        "linux.ebpf.EBPF",
        image,
        volatility,
        python,
        globalargs=["-vvv"],
    )

    if rc != 0 and err.count(b"Unsupported kernel") > 0:
        # The linux-sample-1.bin kernel implementation isn't supported.
        # However, we can still check that the plugin requirements are met.
        return None

    assert rc == 0
    assert out.count(b"\n") > 4


def test_linux_iomem(image, volatility, python):
    rc, out, _err = runvol_plugin("linux.iomem.IOMem", image, volatility, python)

    assert rc == 0
    assert out.count(b"\n") > 100


def test_linux_keyboard_notifiers(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "linux.keyboard_notifiers.Keyboard_notifiers", image, volatility, python
    )

    # linux-sample-1.bin has no suspicious results for this plugin.
    # This validates that plugin requirements are met and exceptions are not raised.
    assert rc == 0
    assert out.count(b"\n") >= 4


def test_linux_kmesg(image, volatility, python):
    rc, out, _err = runvol_plugin("linux.kmsg.Kmsg", image, volatility, python)

    assert rc == 0
    assert out.count(b"\n") > 100


def test_linux_netfilter(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "linux.netfilter.Netfilter", image, volatility, python
    )

    # linux-sample-1.bin has no suspicious results for this plugin.
    # This validates that plugin requirements are met and exceptions are not raised.
    assert rc == 0
    assert out.count(b"\n") >= 4


def test_linux_psscan(image, volatility, python):
    rc, out, _err = runvol_plugin("linux.psscan.PsScan", image, volatility, python)

    assert rc == 0
    assert out.count(b"\n") > 100


def test_linux_hidden_modules(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "linux.hidden_modules.Hidden_modules", image, volatility, python
    )

    # linux-sample-1.bin has no hidden modules.
    # This validates that plugin requirements are met and exceptions are not raised.
    assert rc == 0
    assert out.count(b"\n") >= 4


# MAC


def test_mac_volshell(image, volatility, python):
    basic_volshell_test(image, volatility, python, globalargs=["-m"])


def test_mac_pslist(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.pslist.PsList", image, volatility, python)
    out = out.lower()

    assert (out.find(b"kernel_task") != -1) or (out.find(b"launchd") != -1)
    assert out.count(b"\n") > 10
    assert rc == 0


def test_mac_check_syscall(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "mac.check_syscall.Check_syscall", image, volatility, python
    )
    out = out.lower()

    assert out.find(b"chmod") != -1
    assert out.find(b"chown") != -1
    assert out.find(b"nosys") != -1
    assert out.count(b"\n") > 100
    assert rc == 0


def test_mac_check_sysctl(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "mac.check_sysctl.Check_sysctl", image, volatility, python
    )
    out = out.lower()

    assert out.find(b"__kernel__") != -1
    assert out.count(b"\n") > 250
    assert rc == 0


def test_mac_check_trap_table(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "mac.check_trap_table.Check_trap_table", image, volatility, python
    )
    out = out.lower()

    assert out.count(b"kern_invalid") >= 10
    assert out.count(b"\n") > 50
    assert rc == 0


def test_mac_ifconfig(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.ifconfig.Ifconfig", image, volatility, python)
    out = out.lower()

    assert out.find(b"127.0.0.1") != -1
    assert out.find(b"false") != -1
    assert out.count(b"\n") > 9
    assert rc == 0


def test_mac_lsmod(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.lsmod.Lsmod", image, volatility, python)
    out = out.lower()

    assert out.find(b"com.apple") != -1
    assert out.count(b"\n") > 10
    assert rc == 0


def test_mac_lsof(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.lsof.Lsof", image, volatility, python)
    out = out.lower()

    assert out.count(b"\n") > 50
    assert rc == 0


def test_mac_malfind(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.malfind.Malfind", image, volatility, python)
    out = out.lower()

    assert out.count(b"\n") > 20
    assert rc == 0


def test_mac_mount(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.mount.Mount", image, volatility, python)
    out = out.lower()

    assert out.find(b"/dev") != -1
    assert out.count(b"\n") > 7
    assert rc == 0


def test_mac_netstat(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.netstat.Netstat", image, volatility, python)

    assert out.find(b"TCP") != -1
    assert out.find(b"UDP") != -1
    assert out.find(b"UNIX") != -1
    assert out.count(b"\n") > 10
    assert rc == 0


def test_mac_proc_maps(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.proc_maps.Maps", image, volatility, python)
    out = out.lower()

    assert out.find(b"[heap]") != -1
    assert out.count(b"\n") > 100
    assert rc == 0


def test_mac_psaux(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.psaux.Psaux", image, volatility, python)
    out = out.lower()

    assert out.find(b"executable_path") != -1
    assert out.count(b"\n") > 50
    assert rc == 0


def test_mac_socket_filters(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "mac.socket_filters.Socket_filters", image, volatility, python
    )
    out = out.lower()

    assert out.count(b"\n") > 9
    assert rc == 0


def test_mac_timers(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.timers.Timers", image, volatility, python)
    out = out.lower()

    assert out.count(b"\n") > 6
    assert rc == 0


def test_mac_trustedbsd(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "mac.trustedbsd.Trustedbsd", image, volatility, python
    )
    out = out.lower()

    assert out.count(b"\n") > 10
    assert rc == 0
