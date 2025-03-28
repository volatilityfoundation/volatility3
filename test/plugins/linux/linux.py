import contextlib
import tempfile
import os
import re
from test import test_volatility, LinuxSamples


class TestLinuxVolshell:
    def test_linux_volshell(self, image, volatility, python):
        out = test_volatility.basic_volshell_test(
            image, volatility, python, volshellargs=("-l",)
        )
        assert out.count(b"<task_struct") > 100


class TestLinuxPslist:
    def test_linux_generic_pslist(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.pslist.PsList", image, volatility, python
        )

        assert rc == 0
        out = out.lower()
        assert (out.find(b"init") != -1) or (out.find(b"systemd") != -1)
        assert out.find(b"watchdog") != -1
        assert out.count(b"\n") > 10


class TestLinuxCheckIdt:
    def test_linux_generic_check_idt(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.check_idt.Check_idt", image, volatility, python
        )

        assert rc == 0
        out = out.lower()
        assert out.count(b"__kernel__") >= 10
        assert out.count(b"\n") > 10


class TestLinuxCheckSyscall:
    def test_linux_generic_check_syscall(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.check_syscall.Check_syscall", image, volatility, python
        )

        assert rc == 0
        out = out.lower()
        assert out.find(b"sys_close") != -1
        assert out.find(b"sys_open") != -1
        assert out.count(b"\n") > 100


class TestLinuxLsmod:
    def test_linux_generic_lsmod(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.lsmod.Lsmod", image, volatility, python
        )

        assert rc == 0
        out = out.lower()
        assert out.count(b"\n") > 10


class TestLinuxLsof:
    def test_linux_generic_lsof(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.lsof.Lsof", image, volatility, python
        )

        assert rc == 0
        out = out.lower()
        assert out.count(b"socket:") >= 10
        assert out.count(b"\n") > 35


class TestLinuxProcMaps:
    def test_linux_generic_proc_maps(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.proc.Maps", image, volatility, python
        )

        assert rc == 0
        out = out.lower()
        assert out.count(b"anonymous mapping") >= 10
        assert out.count(b"\n") > 100


class TestLinuxTtyCheck:
    def test_linux_generic_tty_check(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.tty_check.tty_check", image, volatility, python
        )

        assert rc == 0
        out = out.lower()
        assert out.find(b"__kernel__") != -1
        assert out.count(b"\n") >= 5


class TestLinuxSockstat:
    def test_linux_generic_sockstat(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.sockstat.Sockstat", image, volatility, python
        )

        assert rc == 0
        assert out.count(b"AF_UNIX") >= 354
        assert out.count(b"AF_BLUETOOTH") >= 5
        assert out.count(b"AF_INET") >= 32
        assert out.count(b"AF_INET6") >= 20
        assert out.count(b"AF_PACKET") >= 1
        assert out.count(b"AF_NETLINK") >= 43


class TestLinuxLibraryList:
    def test_linux_specific_library_list(self, volatility, python):
        image = LinuxSamples.LINUX_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.library_list.LibraryList",
            image,
            volatility,
            python,
            pluginargs=("--pids", "2363"),
        )

        assert rc == 0
        assert re.search(
            rb"NetworkManager\s2363\s0x7f52cdda0000\s/lib/x86_64-linux-gnu/libnss_files.so.2",
            out,
        )

        assert out.count(b"\n") > 10


class TestLinuxPstree:
    def test_linux_generic_pstree(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.pstree.PsTree", image, volatility, python
        )

        assert rc == 0
        out = out.lower()
        assert (out.find(b"init") != -1) or (out.find(b"systemd") != -1)
        assert out.count(b"\n") > 10


class TestLinuxPidhashtable:
    def test_linux_generic_pidhashtable(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.pidhashtable.PIDHashTable", image, volatility, python
        )

        assert rc == 0
        out = out.lower()
        assert (out.find(b"init") != -1) or (out.find(b"systemd") != -1)
        assert out.count(b"\n") > 10


class TestLinuxBash:
    def test_linux_bash(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.bash.Bash", image, volatility, python
        )

        assert rc == 0
        assert out.count(b"\n") > 10


class TestLinuxBoottime:
    def test_linux_generic_boottime(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.boottime.Boottime", image, volatility, python
        )

        assert rc == 0
        out = out.lower()
        assert out.count(b"utc") >= 1


class TestLinuxCapabilities:
    def test_linux_generic_capabilities(self, image, volatility, python):
        rc, out, err = test_volatility.runvol_plugin(
            "linux.capabilities.Capabilities",
            image,
            volatility,
            python,
            globalargs=("-vvv",),
        )

        if rc != 0 and err.count(b"Unsupported kernel capabilities implementation") > 0:
            # The linux-sample-1.bin kernel implementation isn't supported.
            # However, we can still check that the plugin requirements are met.
            return None

        assert rc == 0
        assert out.count(b"\n") > 10


class TestLinuxCheckCreds:
    def test_linux_generic_check_creds(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.check_creds.Check_creds", image, volatility, python
        )

        # linux-sample-1.bin has no processes sharing credentials.
        # This validates that plugin requirements are met and exceptions are not raised.
        assert rc == 0
        assert out.count(b"\n") >= 4


class TestLinuxElfs:
    def test_linux_generic_elfs(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.elfs.Elfs", image, volatility, python
        )

        assert rc == 0
        assert out.count(b"\n") > 10


class TestLinuxEnvars:
    def test_linux_generic_envars(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.envars.Envars", image, volatility, python
        )

        assert rc == 0
        assert out.count(b"\n") > 10


class TestLinuxKthreads:
    def test_linux_generic_kthreads(self, image, volatility, python):
        rc, out, err = test_volatility.runvol_plugin(
            "linux.kthreads.Kthreads",
            image,
            volatility,
            python,
            globalargs=("-vvv",),
        )

        if rc != 0 and err.count(b"Unsupported kthread implementation") > 0:
            # The linux-sample-1.bin kernel implementation isn't supported.
            # However, we can still check that the plugin requirements are met.
            return None

        assert rc == 0
        assert out.count(b"\n") >= 4


class TestLinuxMalfind:
    def test_linux_generic_malfind(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.malfind.Malfind", image, volatility, python
        )

        # linux-sample-1.bin has no process memory ranges with potential injected code.
        # This validates that plugin requirements are met and exceptions are not raised.
        assert rc == 0
        assert out.count(b"\n") >= 4


class TestLinuxMountinfo:
    def test_linux_generic_mountinfo(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.mountinfo.MountInfo", image, volatility, python
        )

        assert rc == 0
        assert out.count(b"\n") > 10


class TestLinuxPsaux:
    def test_linux_generic_psaux(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.psaux.PsAux", image, volatility, python
        )

        assert rc == 0
        assert out.count(b"\n") > 50


class TestLinuxPtrace:
    def test_linux_generic_ptrace(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.ptrace.Ptrace", image, volatility, python
        )

        # linux-sample-1.bin has no processes being ptraced.
        # This validates that plugin requirements are met and exceptions are not raised.
        assert rc == 0
        assert out.count(b"\n") >= 4


class TestLinuxVmaregexscan:
    def test_linux_generic_vmaregexscan(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.vmaregexscan.VmaRegExScan",
            image,
            volatility,
            python,
            pluginargs=("--pid", "1", "--pattern", "\\x7fELF"),
        )

        assert rc == 0
        assert out.count(b"\n") > 10


class TestLinuxVmayarascanYaraRule:
    def test_linux_specific_vmayarascan_yara_rule(self, volatility, python):
        image = LinuxSamples.LINUX_GENERIC.value.path
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

            rc, out, _err = test_volatility.runvol_plugin(
                "linux.vmayarascan.VmaYaraScan",
                image,
                volatility,
                python,
                pluginargs=("--pid", "8600", "--yara-file", filename),
            )
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.remove(filename)

        assert rc == 0
        assert out.count(b"\n") > 4


class TestLinuxVmayarascanYaraString:
    def test_linux_generic_vmayarascan_yara_string(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.vmayarascan.VmaYaraScan",
            image,
            volatility,
            python,
            pluginargs=("--pid", "1", "--yara-string", "ELF"),
        )

        assert rc == 0
        assert out.count(b"\n") > 10


class TestLinuxPageCacheFiles:
    def test_linux_specific_page_cache_files(self, volatility, python):
        image = LinuxSamples.LINUX_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.pagecache.Files",
            image,
            volatility,
            python,
            pluginargs=("--find", "/etc/passwd"),
        )

        assert rc == 0
        assert out.count(b"\n") > 4

        # inode_num inode_addr ... file_path
        assert re.search(
            rb"146829\s0x88001ab5c270.*?/etc/passwd",
            out,
        )


class TestLinuxPageCacheInodepages:
    def test_linux_specific_page_cache_inodepages(self, volatility, python):
        image = LinuxSamples.LINUX_GENERIC.value.path
        inode_address = hex(0x88001AB5C270)
        inode_dump_filename = f"inode_{inode_address}.dmp"

        rc, out, _err = test_volatility.runvol_plugin(
            "linux.pagecache.InodePages",
            image,
            volatility,
            python,
            pluginargs=("--inode", inode_address),
        )

        assert rc == 0
        assert out.count(b"\n") > 4

        # PageVAddr PagePAddr MappingAddr .. DumpSafe
        assert re.search(
            rb"0xea000054c5f8\s0x18389000\s0x88001ab5c3b0.*?True",
            out,
        )

        try:
            rc, out, _err = test_volatility.runvol_plugin(
                "linux.pagecache.InodePages",
                image,
                volatility,
                python,
                pluginargs=("--inode", inode_address, "--dump"),
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


class TestLinuxCheckAfinfo:
    def test_linux_generic_check_afinfo(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.check_afinfo.Check_afinfo", image, volatility, python
        )

        # linux-sample-1.bin has no suspicious results.
        # This validates that plugin requirements are met and exceptions are not raised.
        assert rc == 0
        assert out.count(b"\n") >= 4


class TestLinuxCheckModules:
    def test_linux_generic_check_modules(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.check_modules.Check_modules", image, volatility, python
        )

        # linux-sample-1.bin has no suspicious results.
        # This validates that plugin requirements are met and exceptions are not raised.
        assert rc == 0
        assert out.count(b"\n") >= 4


class TestLinuxEbpf:
    def test_linux_generic_ebpf_progs(self, image, volatility, python):
        rc, out, err = test_volatility.runvol_plugin(
            "linux.ebpf.EBPF",
            image,
            volatility,
            python,
            globalargs=("-vvv",),
        )

        if rc != 0 and err.count(b"Unsupported kernel") > 0:
            # The linux-sample-1.bin kernel implementation isn't supported.
            # However, we can still check that the plugin requirements are met.
            return None

        assert rc == 0
        assert out.count(b"\n") > 4


class TestLinuxIomem:
    def test_linux_generic_iomem(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.iomem.IOMem", image, volatility, python
        )

        assert rc == 0
        assert out.count(b"\n") > 100


class TestLinuxKeyboardNotifiers:
    def test_linux_generic_keyboard_notifiers(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.keyboard_notifiers.Keyboard_notifiers", image, volatility, python
        )

        # linux-sample-1.bin has no suspicious results for this plugin.
        # This validates that plugin requirements are met and exceptions are not raised.
        assert rc == 0
        assert out.count(b"\n") >= 4


class TestLinuxKmesg:
    def test_linux_generic_kmesg(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.kmsg.Kmsg", image, volatility, python
        )

        assert rc == 0
        assert out.count(b"\n") > 100


class TestLinuxNetfilter:
    def test_linux_generic_netfilter(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.netfilter.Netfilter", image, volatility, python
        )

        # linux-sample-1.bin has no suspicious results for this plugin.
        # This validates that plugin requirements are met and exceptions are not raised.
        assert rc == 0
        assert out.count(b"\n") >= 4


class TestLinuxPsscan:
    def test_linux_generic__psscan(self, image, volatility, python):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.psscan.PsScan", image, volatility, python
        )

        assert rc == 0
        assert out.count(b"\n") > 100


class TestLinuxHiddenModules:
    def test_linux_specific_hidden_modules(self, volatility, python):
        # TODO: this check should be specific, against a distinct infected sample
        image = LinuxSamples.LINUX_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.hidden_modules.Hidden_modules", image, volatility, python
        )

        # linux-sample-1.bin has no hidden modules.
        # This validates that plugin requirements are met and exceptions are not raised.
        assert rc == 0
        assert out.count(b"\n") >= 4


class TestLinuxIpAddr:
    def test_linux_specific_ip_addr(self, volatility, python):
        image = LinuxSamples.LINUX_GENERIC.value.path
        rc, out, err = test_volatility.runvol_plugin(
            "linux.ip.Addr", image, volatility, python
        )

        assert re.search(
            rb"2\s+eth0\s+00:0c:29:8f:ed:ca\s+False\s+192.168.201.161\s+24\s+global\s+UP",
            out,
        )
        assert re.search(
            rb"2\s+eth0\s+00:0c:29:8f:ed:ca\s+False\s+fe80::20c:29ff:fe8f:edca\s+64\s+link\s+UP",
            out,
        )
        assert out.count(b"\n") >= 8
        assert rc == 0


class TestLinuxIpLink:
    def test_linux_specific_ip_link(self, volatility, python):
        image = LinuxSamples.LINUX_GENERIC.value.path
        rc, out, err = test_volatility.runvol_plugin(
            "linux.ip.Link", image, volatility, python
        )

        assert re.search(
            rb"-\s+lo\s+00:00:00:00:00:00\s+UNKNOWN\s+16436\s+noqueue\s+0\s+LOOPBACK,LOWER_UP,UP",
            out,
        )
        assert re.search(
            rb"-\s+eth0\s+00:0c:29:8f:ed:ca\s+UP\s+1500\s+pfifo_fast\s+1000\s+BROADCAST,LOWER_UP,MULTICAST,UP",
            out,
        )
        assert out.count(b"\n") >= 6
        assert rc == 0


class TestLinuxKallsyms:
    def test_linux_specific_kallsyms(self, volatility, python):
        image = LinuxSamples.LINUX_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.kallsyms.Kallsyms",
            image,
            volatility,
            python,
            pluginargs=("--modules",),
        )
        # linux-sample-1.bin has no hidden modules.
        # This validates that plugin requirements are met and exceptions are not raised.
        assert rc == 0
        assert out.count(b"\n") > 1000

        # Addr	Type	Size	Exported	SubSystem	ModuleName	SymbolName	Description
        # 0xffffa009eba9	t	28	False	module	usbcore	usb_mon_register	Symbol is in the text (code) section
        assert re.search(
            rb"0xffffa009eba9\s+t\s+28\s+False\s+module\s+usbcore\s+usb_mon_register\s+Symbol is in the text \(code\) section",
            out,
        )


class TestLinuxPscallstack:
    def test_linux_specific_pscallstack(self, volatility, python):
        image = LinuxSamples.LINUX_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.pscallstack.PsCallStack",
            image,
            volatility,
            python,
            pluginargs=("--pid", "1"),
        )

        assert rc == 0
        assert out.count(b"\n") > 30

        # TID     Comm    Position        Address Value   Name    Type    Module
        # 1       init    39      0x88001f999a40  0xffff81109039  do_select       T       kernel
        assert re.search(
            rb"1\s+init\s+39\s+0x88001f999a40.*?0xffff81109039\s+do_select\s+T\s+kernel",
            out,
        )
