Linux Tutorial
==============

This guide will give you a brief overview of how volatility3 works as well as a demonstration of several of the plugins available in the suite.

Acquiring memory
----------------

Volatility3 does not provide the ability to acquire memory.  Below is an example of a tool that can be used to acquire memory on Linux systems:

* `AVML - Acquire Volatile Memory for Linux <https://github.com/microsoft/avml>`_

Other tools may exist, but please verify their maintenance status and compatibility with volatility3 before use.

Procedure to create symbol tables for Linux
-------------------------------------------

It is recommended to first check the repository `volatility3-symbols <https://github.com/Abyss-W4tcher/volatility3-symbols>`_ for pre-generated JSON.xz symbol table files.  
This repository provides files organized by kernel version for popular Linux distributions such as Debian, Ubuntu, and AlmaLinux.  

If you cannot find a suitable symbol table for your kernel version there, please refer to :ref:`symbol-tables:Mac or Linux symbol tables` to create one manually.  

After creating the file, place it under the directory ``volatility3/symbols``.  
Volatility3 will automatically detect and use symbol tables from this location.



Listing plugins
---------------

Volatility3 currently supports over 40 Linux-specific plugins covering a wide range of forensic analysis needs, such as process enumeration, memory-mapped file inspection, loaded modules, and kernel tracing features.

Some representative plugins include:

- ``linux.pslist``: Lists running processes with their PIDs and PPIDs.
- ``linux.bash``: Recovers bash command history from memory.
- ``linux.lsmod``: Displays loaded kernel modules.
- ``linux.kmsg``: Reads messages from the kernel log buffer.
- ``linux.elfs``: Lists all memory-mapped ELF files.
- ``linux.check_creds``: Checks for suspicious credential structures.
- ``linux.vmayarascan``: Scans process memory using YARA signatures.

For a full list of supported plugins, run the following command:

.. code-block:: shell-session

    $ python3 vol.py --help | grep -i linux.

.. note:: You can also filter and inspect available plugins using more sophisticated patterns or tools like ``grep``, ``awk``, or simply explore the source under ``volatility3/framework/plugins/linux``.


Using plugins
-------------

The following is the syntax to run the volatility CLI.

.. code-block:: shell-session

    $ python3 vol.py -f <path to memory image> <plugin_name> <plugin_option>


Example
-------

banners
~~~~~~~

In this example we will be using a memory dump from the Insomni'hack teaser 2020 CTF Challenge called Getdents.  We will limit the discussion to memory forensics with volatility 3 and not extend it to other parts of the challenge.
Thanks go to `stuxnet <https://github.com/stuxnet999/>`_ for providing this memory dump and `writeup <https://stuxnet999.github.io/dfir/insomnihack-teaser-2020-getdents/>`_.


.. code-block:: shell-session

    $ python3 vol.py -f memory.vmem banners
        
        Volatility 3 Framework 2.26.0

        Progress:  100.00               PDB scanning finished
        Offset  Banner

        0x141c1390      Linux version 4.15.0-42-generic (buildd@lgw01-amd64-023) (gcc version 7.3.0 (Ubuntu 7.3.0-16ubuntu3)) #45-Ubuntu SMP Thu Nov 15 19:32:57 UTC 2018 (Ubuntu 4.15.0-42.45-generic 4.15.18)
        0x63a00160      Linux version 4.15.0-72-generic (buildd@lcy01-amd64-026) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #81-Ubuntu SMP Tue Nov 26 12:20:02 UTC 2019 (Ubuntu 4.15.0-72.81-generic 4.15.18)
        0x6455c4d4      Linux version 4.15.0-72-generic (buildd@lcy01-amd64-026) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #81-Ubuntu SMP Tue Nov 26 12:20:02 UTC 2019 (Ubuntu 4.15.0-72.81-generic 4.15.18)
        0x6e1e055f      Linux version 4.15.0-72-generic (buildd@lcy01-amd64-026) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #81-Ubuntu SMP Tue Nov 26 12:20:02 UTC 2019 (Ubuntu 4.15.0-72.81-generic 4.15.18)
        0x7fde0010      Linux version 4.15.0-72-generic (buildd@lcy01-amd64-026) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #81-Ubuntu SMP Tue Nov 26 12:20:02 UTC 2019 (Ubuntu 4.15.0-72.81-generic 4.15.18)


The above command helps us identify the kernel version and distribution from the memory dump.  
Using this information, follow the instructions in :ref:`getting-started-linux-tutorial:Procedure to create symbol tables for linux` to generate the required ISF file.  
Once created, place the file under the ``volatility3/symbols`` directory so that Volatility3 can recognize it automatically.

linux.boottime
~~~~~~~~~~~~~~

This plugin provides the system boot time extracted from memory.  
It is useful for establishing a timeline, particularly when analyzing incident response scenarios or determining system uptime.

.. code-block:: shell-session

    $ python3 vol.py -f memory.vmem linux.boottime

        Volatility 3 Framework 2.26.0
        Progress:  100.00               Stacking attempts finished

        TIME NS Boot Time

        -       2022-02-10 06:50:16.450008 UTC

This timestamp can serve as a reference point for correlating system events, such as process start times, logs, or malicious activity.


linux.pslist
~~~~~~~~~~~~

This plugin lists active processes by walking the task list from memory.  
It provides detailed metadata for each process, including identifiers and user/group information.

.. code-block:: shell-session

    $ python3 vol.py -f memory.vmem linux.pslist

        Volatility 3 Framework 2.26.0
        Progress:  100.00               Stacking attempts finished
        OFFSET (V)      PID     TID     PPID    COMM    UID     GID     EUID    EGID    CREATION TIME   File output

        0x8ca6db1aac80  1       1       0       systemd 0       0       0       0       2022-02-10 06:50:16.364213 UTC  Disabled
        0x8ca6db1a9640  2       2       0       kthreadd        0       0       0       0       2022-02-10 06:50:16.364213 UTC  Disabled
        0x8ca6db1ac2c0  3       3       2       rcu_gp  0       0       0       0       2022-02-10 06:50:16.372213 UTC  Disabled
        ...

This detailed view allows investigators to correlate user privileges, startup times, and relationships between processes more precisely than before.


linux.pstree
~~~~~~~~~~~~
This plugin presents the process hierarchy as a tree, clearly showing parent-child relationships between processes. 

.. code-block:: shell-session

    $ python3 vol.py -f memory.vmem linux.pstree

        Volatility 3 Framework 2.26.0
        Progress:  100.00               Stacking attempts finished
        OFFSET (V)      PID     TID     PPID    COMM

        0x8ca6db1aac80  1       1       0       systemd
        * 0x8ca6db3342c0        278     278     1       systemd-journal
        * 0x8ca6d005ac80        315     315     1       systemd-udevd
        * 0x8ca6d0eac2c0        478     478     1       systemd-resolve
        * ...
        *** 0x8ca67108c2c0      1507    1507    1438    gdm-x-session
        **** 0x8ca671215900     1527    1527    1507    Xorg
        **** 0x8ca671210000     1608    1608    1507    gnome-session-b
        ***** 0x8ca66fba42c0    1765    1765    1608    ssh-agent

 
It helps identify unusual or suspicious process structures such as orphaned child processes, injected children under legitimate parents, or long chains of shell execution.
The tree view is particularly useful for spotting anomalies in process launch sequences or privilege escalations by inspecting unexpected parent-child relationships.



linux.bash
~~~~~~~~~~

Now to find the commands that were run in the bash shell by using ``linux.bash``.

.. code-block:: shell-session

    $ python3 vol.py -f memory.vmem linux.bash 

        Volatility 3 Framework 2.26.0
        Progress:  100.00               Stacking attempts finished
        PID     Process CommandTime     Command

        1733    bash    2020-01-16 14:00:36.000000      sudo reboot
        1733    bash    2020-01-16 14:00:36.000000      AWAVH��
        1733    bash    2020-01-16 14:00:36.000000      sudo apt upgrade
        1733    bash    2020-01-16 14:00:36.000000      sudo apt upgrade
        1733    bash    2020-01-16 14:00:36.000000      sudo reboot
        1733    bash    2020-01-16 14:00:36.000000      uname -a
        1733    bash    2020-01-16 14:00:41.000000      chmod +x meterpreter
        1733    bash    2020-01-16 14:00:42.000000      sudo ./meterpreter


linux.ip.Addr and linux.ip.Link
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Network configuration is an essential aspect of memory forensics.  
Analyzing the network interfaces and their IP assignments can reveal active connections, misconfigured settings, or even artifacts of malicious activity.

Volatility3 provides the following two plugins to examine this information:

**linux.ip.Addr** displays IP-related metadata for each interface, including IPv4/IPv6 addresses, MAC, scope, and interface status.

.. code-block:: shell-session

    $ python3 vol.py -f memory.vmem linux.ip.Addr

        NetNS   Index   Interface       MAC     Promiscuous     IP      Prefix  Scope Type      State
        4026531992      2       enp0s3  08:00:27:8a:4d:eb       False   10.0.2.15       24      global  UP
        ...

**linux.ip.Link** shows lower-level link information such as MTU, Qdisc, and interface flags.

.. code-block:: shell-session

    $ python3 vol.py -f memory.vmem linux.ip.Link

        NS      Interface       MAC     State   MTU     Qdisc   Qlen    Flags
        4026531992      enp0s3  08:00:27:8a:4d:eb       UP      1500    fq_codel        1000    BROADCAST,LOWER_UP,MULTICAST,UP

Together, these plugins help investigators assess the system’s network exposure and identify anomalies such as multiple network namespaces, unexpected IP addresses, or active interfaces in promiscuous mode.

linux.malfind
~~~~~~~~~~~~~

This plugin scans process memory for suspicious executable regions that may indicate code injection or malicious payloads.  
It is particularly useful for detecting fileless malware, injected shellcode, or unpacked runtime payloads that do not correspond to legitimate binary files on disk.

.. code-block:: shell-session

    $ python3 vol.py -f memory.vmem linux.malfind

        Volatility 3 Framework 2.26.0
        Progress:  100.00               Stacking attempts finished
        PID     Process Start   End     Path    Protection      Hexdump Disasm

        540     networkd-dispat 0x7f1506482000  0x7f1506483000  Anonymous Mapping       rwx
        00 00 00 00 00 00 00 00 43 00 00 00 00 00 00 00 ........C.......
        4c 8d 15 f9 ff ff ff ff 25 03 00 00 00 0f 1f 00 L.......%.......
        ...
        0x7f1506482000: add     byte ptr [rax], al
        0x7f1506482002: add     byte ptr [rax], al
        ...
        0x7f1506482013: stc

In this output:

- **PID / Process**: Identifies the target process (in this case, `networkd-dispat`, PID 540)
- **Start / End**: The memory address range of the suspicious region
- **Path**: Indicates that the region is an anonymous memory mapping (i.e., not backed by a file)
- **Protection**: The region is marked `rwx` (read-write-execute), which is uncommon for legitimate memory regions
- **Disasm**: Shows the disassembled machine code found in that memory region

**Key indicators to focus on:**

- **Anonymous Mapping + rwx**: Memory that is not backed by a file and has execute permissions is often used for injected code
- **Disassembly patterns**: Repetitive `add` instructions, `nop`, or unusual instruction sequences can be artifacts of shellcode, packer stubs, or JIT-compiled code
- **Process context**: The suspicious memory is found in `networkd-dispat`, a system service — if this service is not expected to have dynamic executable memory regions, it may be compromised

Use this plugin early in an investigation to flag processes for deeper inspection.

Further Exploration and Contribution
------------------------------------

This guide has introduced several key Linux plugins available in Volatility 3 for memory forensics.  
However, many more plugins are available, covering topics such as kernel modules, page cache analysis, tracing frameworks, and malware detection.

If you identify gaps in plugin functionality or wish to extend support for a specific analysis use case, you are encouraged to contribute new plugins or enhancements.
Your insights can help shape the future of Linux memory forensics.

