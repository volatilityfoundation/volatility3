import contextlib
import hashlib
import json
import os
import shutil
import tempfile
from test import WindowsSamples, test_volatility


class TestWindowsVolshell:
    def test_windows_volshell(self, image, volatility, python):
        out = test_volatility.basic_volshell_test(
            image, volatility, python, volshellargs=("-w",)
        )
        assert out.count(b"<EPROCESS") > 40


class TestWindowsPslist:
    def test_windows_generic_pslist(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.pslist.PsList",
            image,
            volatility,
            python,
            # Notice that this is needed to hit lru_cache when "specific" will run
            globalargs=("-r", "json"),
        )
        assert rc == 0
        out = out.lower()
        assert out.find(b"system") != -1
        assert out.find(b"csrss.exe") != -1
        assert out.find(b"svchost.exe") != -1
        assert out.count(b"\n") > 10

    def test_windows_specific_pslist(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.pslist.PsList",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        expected_row = {
            "CreateTime": None,
            "ExitTime": None,
            "File output": "Disabled",
            "Handles": 1140,
            "ImageFileName": "System",
            "Offset(V)": 2185004992,
            "PID": 4,
            "PPID": 0,
            "SessionId": None,
            "Threads": 61,
            "Wow64": False,
            "__children": [],
        }
        assert test_volatility.match_output_row(expected_row, json.loads(out))


class TestWindowsPsscan:
    def test_windows_specific_psscan(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.psscan.PsScan", image, volatility, python
        )
        assert rc == 0
        out = out.lower()
        assert out.find(b"system") != -1
        assert out.find(b"csrss.exe") != -1
        assert out.find(b"svchost.exe") != -1
        assert out.count(b"\n") > 10


class TestWindowsDlllist:
    def test_windows_generic_dlllist(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.dlllist.DllList",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 2000
        expected_rows = [
            {
                "Path": "C:\\Windows\\SYSTEM32\\kernel32.dll",
                "Process": "csrss.exe",
            },
            {
                "Path": "C:\\Windows\\system32\\USER32.dll",
                "Process": "csrss.exe",
            },
        ]
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(
                expected_row, json_out, case_sensitive=False
            )


class TestWindowsModules:
    def test_windows_specific_modules(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.modules.Modules",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 110
        expected_rows = [
            {
                "Name": "ntoskrnl.exe",
                "Offset": 2185216944,
                "Path": "\\WINDOWS\\system32\\ntoskrnl.exe",
                "Size": 2179328,
            },
            {
                "Name": "hal.dll",
                "Offset": 2185216840,
                "Path": "\\WINDOWS\\system32\\hal.dll",
                "Size": 81280,
            },
            {
                "Name": "netbios.sys",
                "Offset": 2182050616,
                "Path": "\\SystemRoot\\System32\\DRIVERS\\netbios.sys",
                "Size": 36864,
            },
        ]
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsDumpfiles:
    def test_windows_specific_dumpfiles(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        with open("./test/known_files.json") as json_file:
            known_files = json.load(json_file)

        failed_chksms = 0
        file_name = os.path.basename(image)

        try:
            for addr in known_files["windows_dumpfiles"][file_name]:
                path = tempfile.mkdtemp()

                rc, _out, _err = test_volatility.runvol_plugin(
                    "windows.dumpfiles.DumpFiles",
                    image,
                    volatility,
                    python,
                    globalargs=("-o", path),
                    pluginargs=("--virtaddr", addr),
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


class TestWindowsHandles:
    def test_windows_generic_handles(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.handles.Handles",
            image,
            volatility,
            python,
            pluginargs=("--pid", "4"),
        )
        assert rc == 0
        assert out.find(b"System Pid 4") != -1
        assert (
            out.find(
                b"MACHINE\\SYSTEM\\CONTROLSET001\\CONTROL\\SESSION MANAGER\\MEMORY MANAGEMENT\\PREFETCHPARAMETERS"
            )
            != -1
        )
        assert out.find(b"MACHINE\\SYSTEM\\SETUP") != -1
        assert out.count(b"\n") > 500


class TestWindowsSvcList:
    def test_windows_generic_svclist(self, volatility, python, image):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.svclist.SvcList",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert len(json_out) > 250
        expected_row = {
            "Binary": "\\Driver\\ACPI",
            "Display": "ACPI",
            "Name": "ACPI",
            "Start": "SERVICE_BOOT_START",
            "State": "SERVICE_RUNNING",
            "Type": "SERVICE_KERNEL_DRIVER",
        }
        assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsSvcScan:
    def test_windows_generic_svcscan(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.svcscan.SvcScan",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert len(json_out) > 250
        expected_rows = [
            {"Name": "ACPI", "Type": "SERVICE_KERNEL_DRIVER"},
        ]
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsThrdscan:
    def test_windows_specific_thrdscan(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.thrdscan.ThrdScan", image, volatility, python
        )
        assert rc == 0
        assert out.count(b"\n") > 700
        assert out.find(b"\t1812\t2768\t0x7c810856") != -1
        assert out.find(b"\t840\t2964\t0x7c810856") != -1
        assert out.find(b"\t2536\t2552\t0x7c810856") != -1


class TestWindowsPrivileges:
    def test_windows_generic_privileges(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.privileges.Privs",
            image,
            volatility,
            python,
            pluginargs=("--pid", "4"),
        )
        assert rc == 0
        assert out.find(b"SeCreateTokenPrivilege") != -1
        assert out.find(b"SeCreateGlobalPrivilege") != -1
        assert out.find(b"SeAssignPrimaryTokenPrivilege") != -1
        assert out.count(b"\n") > 20


class TestWindowsGetSIDs:
    def test_windows_generic_getsids(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.getsids.GetSIDs",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 400
        expected_rows = [
            {
                "Name": "Local System",
                "Process": "csrss.exe",
                "SID": "S-1-5-18",
            },
            {
                "Name": "Administrators",
                "Process": "csrss.exe",
                "SID": "S-1-5-32-544",
            },
            {
                "Name": "Everyone",
                "Process": "csrss.exe",
                "SID": "S-1-1-0",
            },
            {
                "Name": "Authenticated Users",
                "Process": "csrss.exe",
                "SID": "S-1-5-11",
            },
            {
                "Name": "System Mandatory Level",
                "Process": "csrss.exe",
                "SID": "S-1-16-16384",
            },
        ]
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsEnvars:
    def test_windows_generic_envars(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.envars.Envars", image, volatility, python
        )
        assert rc == 0
        assert out.find(b"PATH") != -1
        assert out.find(b"PROCESSOR_ARCHITECTURE") != -1
        assert out.find(b"USERNAME") != -1
        assert out.find(b"SystemRoot") != -1
        assert out.find(b"CommonProgramFiles") != -1
        assert out.count(b"\n") > 500


class TestWindowsCallbacks:
    def test_windows_specific_callbacks(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.callbacks.Callbacks", image, volatility, python
        )
        assert rc == 0
        assert out.find(b"PspCreateProcessNotifyRoutine") != -1
        assert out.find(b"KeBugCheckCallbackListHead") != -1
        assert out.find(b"KeBugCheckReasonCallbackListHead") != -1
        assert out.count(b"KeBugCheckReasonCallbackListHead	") > 5


class TestWindowsVadwalk:
    def test_windows_specific_vadwalk(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.vadwalk.VadWalk",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
            pluginargs=("--pid", "4"),
        )
        assert rc == 0
        json_out = json.loads(out)
        expected_rows = test_volatility.load_test_data(
            "windows.vadwalk.VadWalk", "WINDOWS10_GENERIC"
        )
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsDevicetree:
    def test_windows_specific_devicetree(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.devicetree.DeviceTree", image, volatility, python
        )
        assert rc == 0
        assert out.find(b"DEV") != -1
        assert out.find(b"DRV") != -1
        assert out.find(b"ATT") != -1
        assert out.find(b"FILE_DEVICE_CONTROLLER") != -1
        assert out.find(b"FILE_DEVICE_DISK") != -1
        assert out.find(b"FILE_DEVICE_DISK_FILE_SYSTEM") != -1


class TestWindowsVadyarascan:
    def test_windows_specific_vadyarascan_yara_rule(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
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
        fd, filename = tempfile.mkstemp(suffix=".yar")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(yara_rule_01)
            rc, out, _err = test_volatility.runvol_plugin(
                "windows.vadyarascan.VadYaraScan",
                image,
                volatility,
                python,
                pluginargs=("--pid", "4012", "--yara-file", filename),
            )
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.remove(filename)
        assert rc == 0
        assert out.count(b"\n") > 4

    def test_windows_specific_vadyarascan_yara_string(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.vadyarascan.VadYaraScan",
            image,
            volatility,
            python,
            pluginargs=("--pid", "4012", "--yara-string", "MZ"),
        )
        assert rc == 0
        assert out.count(b"\n") > 10


class TestWindowsAmcache:
    def test_windows_generic_amcache(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.amcache.Amcache",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 100
        # Win10+ expected package names
        expected_rows = [
            {
                "Path": "C:\\Windows\\SystemApps\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy",
                "ProductName": "Microsoft.Windows.StartMenuExperienceHost",
            },
            {
                "Path": "C:\\Windows\\SystemApps\\Microsoft.Windows.FileExplorer_cw5n1h2txyewy",
                "ProductName": "c5e2524a-ea46-4f67-841f-6a9465d9d515",
            },
        ]
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsBigPools:
    def test_windows_generic_bigpools(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.bigpools.BigPools",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 2000
        expected_rows = [
            {
                "PoolType": "PagedPool",
            },
            {
                "PoolType": "PagedPoolCacheAligned",
            },
            {
                "PoolType": "NonPagedPoolNx",
            },
        ]
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)


# FIXME: Empty on WIN10 and XP samples
# class TestWindowsCachedump:
#     def test_windows_generic_cachedump(self, volatility, python, image):
#         rc, out, _err = test_volatility.runvol_plugin(
#             "windows.cachedump.Cachedump",
#             image,
#             volatility,
#             python,
#             globalargs=("-r", "json"),
#         )
#         assert rc == 0
#         json_out = json.loads(out)


class TestWindowsCmdLine:
    def test_windows_generic_cmdline(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.cmdline.CmdLine",
            image,
            volatility,
            python,
        )
        assert rc == 0
        assert out.count(b"\n") > 20
        out = out.lower()
        assert (
            out.find(b"C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p".lower())
            != -1
        )
        assert (
            out.count(
                b"C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p".lower()
            )
            > 3
        )


class TestWindowsCmdScan:
    def test_windows_specific_cmdscan(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.cmdscan.CmdScan",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        expected_row = {
            "Process": "conhost.exe",
            "Property": "_COMMAND_HISTORY",
        }
        assert test_volatility.match_output_row(expected_row, json.loads(out))


class TestWindowsConsoles:
    def test_windows_specific_consoles(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.consoles.Consoles",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        expected_row = {
            "Process": "conhost.exe",
            "Property": "_CONSOLE_INFORMATION",
        }
        assert test_volatility.match_output_row(expected_row, json.loads(out))


class TestWindowsCrashinfo:
    def test_windows_specific_crashinfo(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.crashinfo.Crashinfo",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        expected_row = {
            "BitmapHeaderSize": 176128,
            "BitmapPages": 511191,
            "BitmapSize": 1310720,
            "Comment": "PAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGEPAGE",
            "DirectoryTableBase": 4610162688,
            "DumpType": "Bitmap Dump (0x5)",
            "MachineImageType": 34404,
            "MajorVersion": 15,
            "MinorVersion": 19041,
            "NumberProcessors": 1,
            "Signature": "PAGE",
            "SystemTime": "2025-03-06T17:59:20+00:00",
            "SystemUpTime": "0:11:23.199374",
            "__children": [],
        }
        assert test_volatility.match_output_row(expected_row, json.loads(out))


class TestWindowsDriverIrp:
    def test_windows_specific_driverirp(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.driverirp.DriverIrp",
            image,
            volatility,
            python,
        )
        assert rc == 0
        assert out.count(b"\n") > 2000
        assert out.count(b"ntoskrnl") > 400
        for irp in test_volatility.load_test_data(
            "windows.driverirp.DriverIrp", "GENERIC"
        ):
            assert out.find(irp.encode()) != -1


class TestWindowsDriverScan:
    def test_windows_specific_driverscan(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.driverscan.DriverScan",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 50
        expected_rows = [
            {
                "Name": "\\Driver\\ACPI_HAL",
                "Service Key": "\\Driver\\ACPI_HAL",
            },
            {
                "Name": "\\Driver\\Tcpip",
                "Service Key": "Tcpip",
            },
        ]
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsGetServiceSIDs:
    def test_windows_generic_getservicesids(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.getservicesids.GetServiceSIDs",
            image,
            volatility,
            python,
        )
        assert rc == 0
        assert out.count(b"S-1-5-80-") > 90


class TestWindowsIAT:
    def test_windows_generic_iat(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.iat.IAT",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 2000
        expected_rows = [
            {
                "Function": "NtTerminateProcess",
                "Library": "ntdll.dll",
                "Name": "csrss.exe",
            },
            {
                "Function": "RtlSetHeapInformation",
                "Library": "ntdll.dll",
                "Name": "csrss.exe",
            },
        ]
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsInfo:
    def test_windows_specific_info(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.info.Info",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        expected_rows = test_volatility.load_test_data(
            "windows.info.Info", "WINDOWS10_GENERIC"
        )
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsJobLinks:
    def test_windows_specific_joblinks(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.joblinks.JobLinks",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 30
        expected_row = {
            "Active": 1,
            "JobLink": None,
            "JobSess": 2,
            "Name": "taskhostw.exe",
            "Offset(V)": 145201782567040,
            "PID": 4304,
            "PPID": 1008,
            "Process": "(Original Process)",
            "Sess": 2,
            "Term": 0,
            "Total": 1,
            "Wow64": False,
            "__children": [
                {
                    "Active": 0,
                    "JobLink": "Yes",
                    "JobSess": 0,
                    "Name": "taskhostw.exe",
                    "Offset(V)": 145201782567040,
                    "PID": 4304,
                    "PPID": 1008,
                    "Process": "C:\\Windows\\system32\\taskhostw.exe",
                    "Sess": 2,
                    "Term": 0,
                    "Total": 0,
                    "Wow64": False,
                    "__children": [],
                }
            ],
        }

        assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsKPCRs:
    def test_windows_generic_kpcrs(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.kpcrs.KPCRs",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        assert test_volatility.count_entries_flat(json.loads(out)) > 0


class TestWindowsSymlinkScan:
    def test_windows_generic_symlinkscan(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.symlinkscan.SymlinkScan",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        assert test_volatility.count_entries_flat(json.loads(out)) > 0

    def test_windows_specific_symlinkscan(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.symlinkscan.SymlinkScan",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 5
        expected_rows = [
            {
              "CreateTime": "2005-06-25T16:47:28+00:00",
              "From Name": "AUX",
              "Offset": 453082584,
              "To Name": "\\DosDevices\\COM1",
              "__children": []
            },
            {
              "CreateTime": "2005-06-25T16:47:28+00:00",
              "From Name": "UNC",
              "Offset": 453176664,
              "To Name": "\\Device\\Mup",
              "__children": []
            }
        ]

        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsLdrModules:
    def test_windows_specific_ldrmodules(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.ldrmodules.LdrModules",
            image,
            volatility,
            python,
        )
        assert rc == 0
        assert out.count(b"\n") > 800
        out = out.lower()
        assert out.find(b"\\Windows\\System32\\ntdll.dll".lower()) > 10


class TestWindowsLsadump:
    def test_windows_specific_lsadump(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.lsadump.Lsadump",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 5
        expected_row = {
            "Hex": "01 00 00 00 2b 2b f1 09 a3 b3 4b af 02 19 5a 61 2f 09 3a 88 03 52 51 64 8a 6c d2 a8 34 07 cb 61 41 ca a4 5d f1 fb 4c e0 41 72 69 32",
            "Key": "DPAPI_SYSTEM",
        }

        assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsMBRScan:
    def test_windows_specific_mbrscan(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.mbrscan.MBRScan",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 4300
        expected_rows = [
            {
                "Bootcode MD5": "dbcef88b4d770658b0050bf20b2d3061",
                "Disk Signature": "82-78-77-32",
                "Full MBR MD5": "8eea93bb1c63863f6e7f95b084411672",
                "Potential MBR at Physical Offset": 154029739,
            },
            {
                "Bootcode MD5": "591213a9dfef595735e419eff6eeb39d",
                "Disk Signature": "7a-74-60-53",
                "Full MBR MD5": "4e00711a5014941f5ad8b3a4cde69c9c",
                "Potential MBR at Physical Offset": 437808348,
            },
        ]
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsMemmap:
    def test_windows_specific_memmap(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.memmap.Memmap",
            image,
            volatility,
            python,
            pluginargs=("--pid", "504"),
        )
        assert rc == 0
        assert out.count(b"\n") > 12000


class TestWindowsMFTscan:
    def test_windows_specific_mftscan_ads_xp(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.mftscan.ADS",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        expected_rows = [
            {
                "ADS Filename": "Zone.Identifier",
                "Filename": "libby_hoeler_part1.wmv",
                "Hexdump": "5b 5a 6f 6e 65 54 72 61 6e 73 66 65 72 5d 0d 0a 5a 6f 6e 65 49 64 3d 33 0d 0a",
                "MFT Type": "DATA",
                "Offset": 55926304,
                "Record Number": 323,
                "Record Type": "FILE",
                "__children": [],
            },
            {
                "ADS Filename": "Zone.Identifier",
                "Filename": "NetZeroQuickHelpLite.exe",
                "Hexdump": "5b 5a 6f 6e 65 54 72 61 6e 73 66 65 72 5d 0d 0a 5a 6f 6e 65 49 64 3d 33 0d 0a",
                "MFT Type": "DATA",
                "Offset": 56102400,
                "Record Number": 347,
                "Record Type": "FILE",
                "__children": [],
            },
        ]
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)

    def test_windows_specific_mftscan_ads_win10(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.mftscan.ADS",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        expected_rows = [
            {
                "ADS Filename": "$Max",
                "Filename": "$UsnJrnl",
                "Hexdump": "00 00 00 02 00 00 00 00 00 00 80 00 00 00 00 00 b9 dd f0 cc df 73 db 01 00 00 00 00 00 00 00 00",
                "MFT Type": "DATA",
                "Offset": 26235616,
                "Record Number": 107240,
                "Record Type": "FILE",
                "__children": [],
            },
            {
                "ADS Filename": "$SRAT",
                "Filename": "$Bitmap",
                "Hexdump": "a4 5f fd 60 38 00 01 03 10 00 0c 00 04 00 00 00 01 00 00 00 01 00 00 00 8d 4e 16 00 02 00 00 00 a0 00 00 00 00 00 06 00 03 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4a 7b 01 00 00 00 00 00",
                "MFT Type": "DATA",
                "Offset": 1052277088,
                "Record Number": 6,
                "Record Type": "FILE",
                "__children": [],
            },
        ]
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)

    def test_windows_specific_mftscan_mftscan(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.mftscan.MFTScan",
            image,
            volatility,
            python,
        )
        assert rc == 0
        assert out.count(b"\n") > 15000
        assert out.count(b"STANDARD_INFORMATION") > 5000
        assert out.count(b"FILE_NAME") > 11000

    def test_windows_specific_mftscan_residentdata_win10(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.mftscan.ResidentData",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 850
        expected_rows = [
            {
                "Filename": "index",
                "Hexdump": "30 5c 72 a7 1b 6d fb fc 09 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "MFT Type": "DATA",
                "Offset": 4961536280,
                "Record Number": 116474,
                "Record Type": "FILE",
            },
            {
                "Filename": "0.2.filtertrie.intermediate.txt",
                "Hexdump": "30 09 32 0d 0a",
                "MFT Type": "DATA",
                "Offset": 619242944,
                "Record Number": 113013,
                "Record Type": "FILE",
            },
        ]
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsModScan:
    def test_windows_generic_modscan(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.modscan.ModScan",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 90
        expected_rows = [
            {
                "Name": "ntoskrnl.exe",
                "Offset": 37733296,
                "Path": "\\WINDOWS\\system32\\ntoskrnl.exe",
                "Size": 2179328,
            },
            {
                "Name": "hal.dll",
                "Offset": 37733192,
                "Path": "\\WINDOWS\\system32\\hal.dll",
                "Size": 81280,
            },
            {
                "Name": "netbios.sys",
                "Offset": 34566968,
                "Path": "\\SystemRoot\\System32\\DRIVERS\\netbios.sys",
                "Size": 36864,
            },
        ]
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsMutantScan:
    def test_windows_specific_mutantscan(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.mutantscan.MutantScan",
            image,
            volatility,
            python,
        )
        assert rc == 0
        assert out.count(b"\n") > 350


class TestWindowsNetScan:
    def test_windows_specific_netscan(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.netscan.NetScan",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 100
        expected_rows = [
            {
                "Created": "2025-03-06T17:56:53+00:00",
                "ForeignAddr": "13.107.246.254",
                "ForeignPort": 443,
                "LocalAddr": "10.0.0.4",
                "LocalPort": 49929,
                "Offset": 145201667934000,
                "Owner": "SearchApp.exe",
                "PID": 5644,
                "Proto": "TCPv4",
                "State": "CLOSE_WAIT",
            },
            {
                "Created": "2025-03-06T17:50:02+00:00",
                "ForeignAddr": "168.63.129.16",
                "ForeignPort": 80,
                "LocalAddr": "10.0.0.4",
                "LocalPort": 49689,
                "Offset": 145201778694688,
                "Owner": "WindowsAzureGu",
                "PID": 1944,
                "Proto": "TCPv4",
                "State": "CLOSED",
            },
        ]
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsNetStat:
    def test_windows_specific_netstat(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.netstat.NetStat",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 70
        expected_rows = [
            {
                "Created": "2025-03-06T17:56:53+00:00",
                "ForeignAddr": "13.107.246.254",
                "ForeignPort": 443,
                "LocalAddr": "10.0.0.4",
                "LocalPort": 49929,
                "Offset": 145201667934000,
                "Owner": "SearchApp.exe",
                "PID": 5644,
                "Proto": "TCPv4",
                "State": "CLOSE_WAIT",
            },
            {
                "Created": "2025-03-06T17:50:02+00:00",
                "ForeignAddr": "168.63.129.16",
                "ForeignPort": 80,
                "LocalAddr": "10.0.0.4",
                "LocalPort": 49688,
                "Offset": 145201778506032,
                "Owner": "WindowsAzureGu",
                "PID": 1944,
                "Proto": "TCPv4",
                "State": "ESTABLISHED",
            },
        ]
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsPESymbols:
    def test_windows_specific_pe_symbols_processes(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.pe_symbols.PESymbols",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
            pluginargs=(
                "--source",
                "processes",
                "--module",
                "ntdll.dll",
                "--symbol",
                "NtProtectVirtualMemory",
            ),
        )
        assert rc == 0
        expected_row = {
            "Address": 2089868982,
            "Module": "ntdll.dll",
            "Symbol": "NtProtectVirtualMemory",
        }

        assert test_volatility.match_output_row(expected_row, json.loads(out))

    def test_windows_specific_pe_symbols_kernel(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.pe_symbols.PESymbols",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
            pluginargs=(
                "--source",
                "kernel",
                "--module",
                "ntoskrnl.exe",
                "--symbol",
                "ZwOpenThread",
            ),
        )
        assert rc == 0
        expected_row = {
            "Address": 2152583356,
            "Module": "ntoskrnl.exe",
            "Symbol": "ZwOpenThread",
        }

        assert test_volatility.match_output_row(expected_row, json.loads(out))


class TestWindowsPoolScanner:
    def test_windows_specific_poolscanner(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.poolscanner.PoolScanner",
            image,
            volatility,
            python,
        )
        assert rc == 0
        assert out.count(b"\n") > 4800
        assert out.find(b"_FILE_OBJECT") != -1
        assert out.find(b"_ETHREAD") != -1
        assert out.find(b"_RTL_ATOM_TABLE") != -1
        assert out.find(b"_KMUTANT") != -1


class TestWindowsPsTree:
    def test_windows_specific_pstree(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.pstree.PsTree",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 110
        expected_row = test_volatility.load_test_data(
            "windows.pstree.PsTree", "WINDOWS10_GENERIC"
        )

        assert test_volatility.match_output_row(
            expected_row, json_out, children_recursive=True
        )


class TestWindowsRegistry:
    def test_windows_specific_registry_certificates(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.registry.certificates.Certificates",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 30
        expected_row = {
            "Certificate ID": "ProtectedRoots",
            "Certificate path": "Software\\Microsoft\\SystemCertificates",
            "Certificate section": "Root",
        }
        assert test_volatility.match_output_row(expected_row, json_out)

    def test_windows_generic_registry_hivelist(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.registry.hivelist.HiveList", image, volatility, python
        )
        assert rc == 0
        out = out.lower()

        not_xp = out.find(b"\\systemroot\\system32\\config\\software")
        if not_xp == -1:
            assert (
                out.find(
                    b"\\device\\harddiskvolume1\\windows\\system32\\config\\software"
                )
                != -1
            )
        assert out.count(b"\n") > 10

    def test_windows_specific_registry_hivescan(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.registry.hivescan.HiveScan",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        expected_rows = test_volatility.load_test_data(
            "windows.registry.hivescan.HiveScan", "WINDOWS10_GENERIC"
        )
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)

    def test_windows_specific_registry_printkey(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.registry.printkey.PrintKey",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 450
        expected_rows = test_volatility.load_test_data(
            "windows.registry.printkey.PrintKey", "WINDOWS10_GENERIC"
        )
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)

    def test_windows_specific_registry_userassist(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.registry.userassist.UserAssist",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 35
        expected_row = test_volatility.load_test_data(
            "windows.registry.userassist.UserAssist", "WINDOWS10_GENERIC"
        )
        assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsSessions:
    def test_windows_specific_sessions(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.sessions.Sessions",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 115
        expected_rows = test_volatility.load_test_data(
            "windows.sessions.Sessions", "WINDOWS10_GENERIC"
        )
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsShimcacheMem:
    def test_windows_specific_shimcachemem(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.shimcachemem.ShimcacheMem",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        expected_rows = test_volatility.load_test_data(
            "windows.shimcachemem.ShimcacheMem", "WINDOWS10_GENERIC"
        )
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsSSDT:
    def test_windows_specific_ssdt(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.ssdt.SSDT",
            image,
            volatility,
            python,
        )
        assert rc == 0
        assert out.count(b"\n") > 770
        assert out.find(b"ntoskrnl") != -1
        assert out.find(b"Nt") != -1
        assert out.find(b"xHal") != -1


class TestWindowsThreads:
    def test_windows_specific_threads(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.threads.Threads",
            image,
            volatility,
            python,
        )
        assert rc == 0
        assert out.count(b"\n") > 1730


class TestWindowsTimers:
    def test_windows_specific_timers(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.timers.Timers",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        expected_rows = test_volatility.load_test_data(
            "windows.timers.Timers", "WINDOWSXP_GENERIC"
        )
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsVadInfo:
    def test_windows_specific_vadinfo(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.vadinfo.VadInfo",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
            pluginargs=("--pid", "4"),
        )
        assert rc == 0
        json_out = json.loads(out)
        expected_rows = test_volatility.load_test_data(
            "windows.vadinfo.VadInfo", "WINDOWS10_GENERIC"
        )
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsVerInfo:
    def test_windows_specific_verinfo(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.verinfo.VerInfo",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        assert test_volatility.count_entries_flat(json_out) > 125
        expected_row = {
            "Base": 2152558592,
            "Build": 2622,
            "Major": 5,
            "Minor": 1,
            "Name": "ntoskrnl.exe",
            "Product": 2600,
            "__children": [],
        }
        assert test_volatility.match_output_row(expected_row, json_out)


class TestWindowsVirtMap:
    def test_windows_specific_virtmap(self, volatility, python):
        image = WindowsSamples.WINDOWS10_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.virtmap.VirtMap",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        json_out = json.loads(out)
        expected_rows = test_volatility.load_test_data(
            "windows.virtmap.VirtMap", "WINDOWS10_GENERIC"
        )
        for expected_row in expected_rows:
            assert test_volatility.match_output_row(expected_row, json_out)
