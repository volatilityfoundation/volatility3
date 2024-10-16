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


def runvol_plugin(
    plugin,
    img,
    volatility,
    python,
    remote_isf_url=None,
    pluginargs=None,
    globalargs=None,
):
    plugin_args = [plugin]
    plugin_args += pluginargs if pluginargs else []
    global_args = globalargs or []

    common_args = [
        "--single-location",
        img,
        "-q",
    ]
    if remote_isf_url:
        common_args += ["--remote-isf-url", remote_isf_url]

    final_args = global_args + common_args + plugin_args

    return runvol(final_args, volatility, python)


#
# TESTS
#

# WINDOWS


def test_windows_pslist(image, volatility, python):
    rc, out, err = runvol_plugin("windows.pslist.PsList", image, volatility, python)
    out = out.lower()
    assert out.find(b"system") != -1
    assert out.find(b"csrss.exe") != -1
    assert out.find(b"svchost.exe") != -1
    assert out.count(b"\n") > 10
    assert rc == 0

    rc, out, err = runvol_plugin(
        "windows.pslist.PsList", image, volatility, python, pluginargs=["--pid", "4"]
    )
    out = out.lower()
    assert out.find(b"system") != -1
    assert out.count(b"\n") < 10
    assert rc == 0


def test_windows_psscan(image, volatility, python):
    rc, out, err = runvol_plugin("windows.psscan.PsScan", image, volatility, python)
    out = out.lower()
    assert out.find(b"system") != -1
    assert out.find(b"csrss.exe") != -1
    assert out.find(b"svchost.exe") != -1
    assert out.count(b"\n") > 10
    assert rc == 0


def test_windows_dlllist(image, volatility, python):
    rc, out, err = runvol_plugin("windows.dlllist.DllList", image, volatility, python)
    out = out.lower()
    assert out.count(b"\n") > 10
    assert rc == 0


def test_windows_modules(image, volatility, python):
    rc, out, err = runvol_plugin("windows.modules.Modules", image, volatility, python)
    out = out.lower()
    assert out.count(b"\n") > 10
    assert rc == 0


def test_windows_hivelist(image, volatility, python):
    rc, out, err = runvol_plugin(
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

            rc, out, err = runvol_plugin(
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
    rc, out, err = runvol_plugin(
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
    rc, out, err = runvol_plugin("windows.svcscan.SvcScan", image, volatility, python)

    assert out.find(b"Microsoft ACPI Driver") != -1
    assert out.count(b"\n") > 250
    assert rc == 0


def test_windows_thrdscan(image, volatility, python):
    rc, out, err = runvol_plugin("windows.thrdscan.ThrdScan", image, volatility, python)
    # find pid 4 (of system process) which starts with lowest tids
    assert out.find(b"\t4\t8") != -1
    assert out.find(b"\t4\t12") != -1
    assert out.find(b"\t4\t16") != -1
    #assert out.find(b"this raieses AssertionError") != -1
    assert rc == 0


def test_windows_privileges(image, volatility, python):
    rc, out, err = runvol_plugin(
        "windows.privileges.Privs", image, volatility, python, pluginargs=["--pid", "4"]
    )

    assert out.find(b"SeCreateTokenPrivilege") != -1
    assert out.find(b"SeCreateGlobalPrivilege") != -1
    assert out.find(b"SeAssignPrimaryTokenPrivilege") != -1
    assert out.count(b"\n") > 20
    assert rc == 0


def test_windows_getsids(image, volatility, python):
    rc, out, err = runvol_plugin(
        "windows.getsids.GetSIDs", image, volatility, python, pluginargs=["--pid", "4"]
    )

    assert out.find(b"Local System") != -1
    assert out.find(b"Administrators") != -1
    assert out.find(b"Everyone") != -1
    assert out.find(b"Authenticated Users") != -1
    assert rc == 0


def test_windows_envars(image, volatility, python):
    rc, out, err = runvol_plugin("windows.envars.Envars", image, volatility, python)

    assert out.find(b"PATH") != -1
    assert out.find(b"PROCESSOR_ARCHITECTURE") != -1
    assert out.find(b"USERNAME") != -1
    assert out.find(b"SystemRoot") != -1
    assert out.find(b"CommonProgramFiles") != -1
    assert out.count(b"\n") > 500
    assert rc == 0


def test_windows_callbacks(image, volatility, python):
    rc, out, err = runvol_plugin(
        "windows.callbacks.Callbacks", image, volatility, python
    )

    assert out.find(b"PspCreateProcessNotifyRoutine") != -1
    assert out.find(b"KeBugCheckCallbackListHead") != -1
    assert out.find(b"KeBugCheckReasonCallbackListHead") != -1
    assert out.count(b"KeBugCheckReasonCallbackListHead	") > 5
    assert rc == 0


def test_windows_vadwalk(image, volatility, python):
    rc, out, err = runvol_plugin("windows.vadwalk.VadWalk", image, volatility, python)

    assert out.find(b"Vad") != -1
    assert out.find(b"VadS") != -1
    assert out.find(b"Vadl") != -1
    assert out.find(b"VadF") != -1
    assert out.find(b"0x0") != -1
    assert rc == 0


def test_windows_devicetree(image, volatility, python):
    rc, out, err = runvol_plugin(
        "windows.devicetree.DeviceTree", image, volatility, python
    )

    assert out.find(b"DEV") != -1
    assert out.find(b"DRV") != -1
    assert out.find(b"ATT") != -1
    assert out.find(b"FILE_DEVICE_CONTROLLER") != -1
    assert out.find(b"FILE_DEVICE_DISK") != -1
    assert out.find(b"FILE_DEVICE_DISK_FILE_SYSTEM") != -1
    assert rc == 0


# LINUX


def test_linux_pslist(image, volatility, python, remote_isf_url):
    rc, out, err = runvol_plugin(
        "linux.pslist.PsList", image, volatility, python, remote_isf_url
    )
    out = out.lower()

    assert (out.find(b"init") != -1) or (out.find(b"systemd") != -1)
    assert out.find(b"watchdog") != -1
    assert out.count(b"\n") > 10
    assert rc == 0


def test_linux_check_idt(image, volatility, python, remote_isf_url):
    rc, out, err = runvol_plugin(
        "linux.check_idt.Check_idt", image, volatility, python, remote_isf_url
    )
    out = out.lower()

    assert out.count(b"__kernel__") >= 10
    assert out.count(b"\n") > 10
    assert rc == 0


def test_linux_check_syscall(image, volatility, python, remote_isf_url):
    rc, out, err = runvol_plugin(
        "linux.check_syscall.Check_syscall", image, volatility, python, remote_isf_url
    )
    out = out.lower()

    assert out.find(b"sys_close") != -1
    assert out.find(b"sys_open") != -1
    assert out.count(b"\n") > 100
    assert rc == 0


def test_linux_lsmod(image, volatility, python, remote_isf_url):
    rc, out, err = runvol_plugin(
        "linux.lsmod.Lsmod", image, volatility, python, remote_isf_url
    )
    out = out.lower()

    assert out.count(b"\n") > 10
    assert rc == 0


def test_linux_lsof(image, volatility, python, remote_isf_url):
    rc, out, err = runvol_plugin(
        "linux.lsof.Lsof", image, volatility, python, remote_isf_url
    )
    out = out.lower()

    assert out.count(b"socket:") >= 10
    assert out.count(b"\n") > 35
    assert rc == 0


def test_linux_proc_maps(image, volatility, python, remote_isf_url):
    rc, out, err = runvol_plugin(
        "linux.proc.Maps", image, volatility, python, remote_isf_url
    )
    out = out.lower()

    assert out.count(b"anonymous mapping") >= 10
    assert out.count(b"\n") > 100
    assert rc == 0


def test_linux_tty_check(image, volatility, python, remote_isf_url):
    rc, out, err = runvol_plugin(
        "linux.tty_check.tty_check", image, volatility, python, remote_isf_url
    )
    out = out.lower()

    assert out.find(b"__kernel__") != -1
    assert out.count(b"\n") >= 5
    assert rc == 0


def test_linux_sockstat(image, volatility, python, remote_isf_url):
    rc, out, err = runvol_plugin(
        "linux.sockstat.Sockstat", image, volatility, python, remote_isf_url
    )

    assert out.count(b"AF_UNIX") >= 354
    assert out.count(b"AF_BLUETOOTH") >= 5
    assert out.count(b"AF_INET") >= 32
    assert out.count(b"AF_INET6") >= 20
    assert out.count(b"AF_PACKET") >= 1
    assert out.count(b"AF_NETLINK") >= 43
    assert rc == 0


def test_linux_library_list(image, volatility, python, remote_isf_url):
    rc, out, err = runvol_plugin(
        "linux.library_list.LibraryList", image, volatility, python, remote_isf_url
    )

    assert re.search(
        rb"NetworkManager\s2363\s0x7f52cdda0000\s/lib/x86_64-linux-gnu/libnss_files.so.2",
        out,
    )
    assert re.search(
        rb"gnome-settings-\s3807\s0x7f7e660b5000\s/lib/x86_64-linux-gnu/libbz2.so.1.0",
        out,
    )
    assert re.search(
        rb"gdu-notificatio\s3878\s0x7f25ce33e000\s/usr/lib/x86_64-linux-gnu/libXau.so.6",
        out,
    )
    assert re.search(
        rb"bash\s8600\s0x7fe78a85f000\s/lib/x86_64-linux-gnu/libnss_files.so.2",
        out,
    )

    assert out.count(b"\n") >= 2677
    assert rc == 0


# MAC


def test_mac_pslist(image, volatility, python):
    rc, out, err = runvol_plugin("mac.pslist.PsList", image, volatility, python)
    out = out.lower()

    assert (out.find(b"kernel_task") != -1) or (out.find(b"launchd") != -1)
    assert out.count(b"\n") > 10
    assert rc == 0


def test_mac_check_syscall(image, volatility, python):
    rc, out, err = runvol_plugin(
        "mac.check_syscall.Check_syscall", image, volatility, python
    )
    out = out.lower()

    assert out.find(b"chmod") != -1
    assert out.find(b"chown") != -1
    assert out.find(b"nosys") != -1
    assert out.count(b"\n") > 100
    assert rc == 0


def test_mac_check_sysctl(image, volatility, python):
    rc, out, err = runvol_plugin(
        "mac.check_sysctl.Check_sysctl", image, volatility, python
    )
    out = out.lower()

    assert out.find(b"__kernel__") != -1
    assert out.count(b"\n") > 250
    assert rc == 0


def test_mac_check_trap_table(image, volatility, python):
    rc, out, err = runvol_plugin(
        "mac.check_trap_table.Check_trap_table", image, volatility, python
    )
    out = out.lower()

    assert out.count(b"kern_invalid") >= 10
    assert out.count(b"\n") > 50
    assert rc == 0


def test_mac_ifconfig(image, volatility, python):
    rc, out, err = runvol_plugin("mac.ifconfig.Ifconfig", image, volatility, python)
    out = out.lower()

    assert out.find(b"127.0.0.1") != -1
    assert out.find(b"false") != -1
    assert out.count(b"\n") > 9
    assert rc == 0


def test_mac_lsmod(image, volatility, python):
    rc, out, err = runvol_plugin("mac.lsmod.Lsmod", image, volatility, python)
    out = out.lower()

    assert out.find(b"com.apple") != -1
    assert out.count(b"\n") > 10
    assert rc == 0


def test_mac_lsof(image, volatility, python):
    rc, out, err = runvol_plugin("mac.lsof.Lsof", image, volatility, python)
    out = out.lower()

    assert out.count(b"\n") > 50
    assert rc == 0


def test_mac_malfind(image, volatility, python):
    rc, out, err = runvol_plugin("mac.malfind.Malfind", image, volatility, python)
    out = out.lower()

    assert out.count(b"\n") > 20
    assert rc == 0


def test_mac_mount(image, volatility, python):
    rc, out, err = runvol_plugin("mac.mount.Mount", image, volatility, python)
    out = out.lower()

    assert out.find(b"/dev") != -1
    assert out.count(b"\n") > 7
    assert rc == 0


def test_mac_netstat(image, volatility, python):
    rc, out, err = runvol_plugin("mac.netstat.Netstat", image, volatility, python)

    assert out.find(b"TCP") != -1
    assert out.find(b"UDP") != -1
    assert out.find(b"UNIX") != -1
    assert out.count(b"\n") > 10
    assert rc == 0


def test_mac_proc_maps(image, volatility, python):
    rc, out, err = runvol_plugin("mac.proc_maps.Maps", image, volatility, python)
    out = out.lower()

    assert out.find(b"[heap]") != -1
    assert out.count(b"\n") > 100
    assert rc == 0


def test_mac_psaux(image, volatility, python):
    rc, out, err = runvol_plugin("mac.psaux.Psaux", image, volatility, python)
    out = out.lower()

    assert out.find(b"executable_path") != -1
    assert out.count(b"\n") > 50
    assert rc == 0


def test_mac_socket_filters(image, volatility, python):
    rc, out, err = runvol_plugin(
        "mac.socket_filters.Socket_filters", image, volatility, python
    )
    out = out.lower()

    assert out.count(b"\n") > 9
    assert rc == 0


def test_mac_timers(image, volatility, python):
    rc, out, err = runvol_plugin("mac.timers.Timers", image, volatility, python)
    out = out.lower()

    assert out.count(b"\n") > 6
    assert rc == 0


def test_mac_trustedbsd(image, volatility, python):
    rc, out, err = runvol_plugin("mac.trustedbsd.Trustedbsd", image, volatility, python)
    out = out.lower()

    assert out.count(b"\n") > 10
    assert rc == 0
