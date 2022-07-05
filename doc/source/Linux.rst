Linux Tutorial
==============

This guide gives you a brief introduction to how volatility3 works and some demonstration of several of the plugins available from

Acquiring memory
----------------

Volatility3 does not provide the ability to acquire memory. In this tutorial we will see how we can use  `LiME <https://github.com/504ensicslabs/lime>`_ for this purpose. 
It supports 32 and 64 bit captures from native Intel hardware as well as virtual machine guests. 
It also supports capture from Android devices. See below for example commands building and running LiME:

.. code-block:: shell-session

    $ tar -xvzf lime-forensics-1.1-r14.tar.gz 
    $ cd lime-forensics-1.1-r14/src
    $ make
    ....
      CC [M]  lime-forensics-1.1-r14/src/tcp.o
      CC [M]  lime-forensics-1.1-r14/src/disk.o
    ....
    $ sudo insmod lime-3.2.0-23-generic.ko "path=/tmp/ubuntu.lime format=lime"
    $ ls -alh /tmp/ubuntu.lime 
    -r--r--r-- 1 root root 2.0G Aug 17 19:37 /tmp/ubuntu.lime

Procedure to create symbol tables for linux
--------------------------------------------

To create a symbol table please refer this :ref:`symbol-tables:Mac or Linux symbol tables`.

.. tip:: We can also find some ISF files from `Linux ISF Server <https://isf-server.techanarchy.net/>`_ ,  which is built and maintained by `kevthehermit <https://twitter.com/kevthehermit>`_.
        After creating the file or downloading the file from the ISF server, please place the file under the directory ``volatility3/symbols/linux``. Make a directory linux under symbols.


Listing plugins
---------------

Following are the sample of linux plugins available for volatility3. More plugins will be available on future releases.
For plugin requests, Please create an issue with description of the plugin.

.. code-block:: shell-session

    $ python3 vol.py --help | grep -i linux. | head -n 5
        banners.Banners     Attempts to identify potential linux banners in an
        linux.bash.Bash     Recovers bash command history from memory.
        linux.check_afinfo.Check_afinfo
        linux.check_creds.Check_creds
        linux.check_idt.Check_idt

.. note:: Here the the command is piped to grep and head in-order to give you sample list of plugins.


Using plugins
-------------

The following is the syntax to run volatility tool.

.. code-block:: shell-session

    $ python3 vol.py -f <path to memory image> <plugin_name> <plugin_option>


Example
-------

Example 1
~~~~~~~~~

In this example we will be using memory dump from Insomni'hack teaser 2020 CTF. Challenge name Getdents.  We will limit the discussion to memory forensics with volatility3 and not extend to other parts of the challenges.
I'd like to say thanks to `stuxnet <https://github.com/stuxnet999/>`_ for providing this memory dump and `writeup <https://stuxnet999.github.io/insomnihack/2020/09/17/Insomihack-getdents.html>`_.


.. code-block:: shell-session

    $ python3 vol.py -f memory.vmem banners
        
        Volatility 3 Framework 2.0.3

        Progress:  100.00               PDB scanning finished
        Offset  Banner

        0x141c1390      Linux version 4.15.0-42-generic (buildd@lgw01-amd64-023) (gcc version 7.3.0 (Ubuntu 7.3.0-16ubuntu3)) #45-Ubuntu SMP Thu Nov 15 19:32:57 UTC 2018 (Ubuntu 4.15.0-42.45-generic 4.15.18)
        0x63a00160      Linux version 4.15.0-72-generic (buildd@lcy01-amd64-026) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #81-Ubuntu SMP Tue Nov 26 12:20:02 UTC 2019 (Ubuntu 4.15.0-72.81-generic 4.15.18)
        0x6455c4d4      Linux version 4.15.0-72-generic (buildd@lcy01-amd64-026) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #81-Ubuntu SMP Tue Nov 26 12:20:02 UTC 2019 (Ubuntu 4.15.0-72.81-generic 4.15.18)
        0x6e1e055f      Linux version 4.15.0-72-generic (buildd@lcy01-amd64-026) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #81-Ubuntu SMP Tue Nov 26 12:20:02 UTC 2019 (Ubuntu 4.15.0-72.81-generic 4.15.18)
        0x7fde0010      Linux version 4.15.0-72-generic (buildd@lcy01-amd64-026) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #81-Ubuntu SMP Tue Nov 26 12:20:02 UTC 2019 (Ubuntu 4.15.0-72.81-generic 4.15.18)


This above command helps us to find the memory dump's kernel version and the distribution version. Now using the above banner we can search for ISF file from the ISF server.
If you do not find the ISF file then, please follow the instructions on :ref:`Linux:Procedure to create symbol tables for linux`. After that place the ISF file under ``volatility3/symbols/linux`` directory.

.. tip:: Use the banner text which is most repeated to search from ISF Server.


.. code-block:: shell-session

    $ python3 vol.py -f memory.vmem linux.pslist

        Volatility 3 Framework 2.0.3    Stacking attempts finished

        PID     PPID    COMM

        1       0       systemd
        2       0       kthreadd
        3       2       kworker/0:0
        4       2       kworker/0:0H
        5       2       kworker/u256:0
        6       2       mm_percpu_wq
        7       2       ksoftirqd/0
        8       2       rcu_sched
        9       2       rcu_bh
        10      2       migration/0
        11      2       watchdog/0
        12      2       cpuhp/0
        13      2       kdevtmpfs
        14      2       netns
        15      2       rcu_tasks_kthre
        16      2       kauditd
        .....

``linux.pslist`` helps us to list the processes which are running, their PIDs and PPIDs.

.. code-block:: shell-session

    $ python3 vol.py -f memory.vmem linux.pstree
        Volatility 3 Framework 2.0.3
        Progress:  100.00               Stacking attempts finished
        PID     PPID    COMM

        1       0       systemd
        * 636   1       polkitd
        * 514   1       acpid
        * 1411  1       pulseaudio
        * 517   1       rsyslogd
        * 637   1       cups-browsed
        * 903   1       whoopsie
        * 522   1       ModemManager
        * 525   1       cron
        * 526   1       avahi-daemon
        ** 542  526     avahi-daemon
        * 657   1       unattended-upgr
        * 914   1       kerneloops
        * 532   1       dbus-daemon
        * 1429  1       ibus-x11
        * 929   1       kerneloops
        * 1572  1       gsd-printer
        * 933   1       upowerd
        * 1071  1       rtkit-daemon
        * 692   1       gdm3
        ** 1234 692     gdm-session-wor
        *** 1255        1234    gdm-x-session
        **** 1257       1255    Xorg
        **** 1266       1255    gnome-session-b
        ***** 1537      1266    gsd-clipboard
        ***** 1539      1266    gsd-color
        ***** 1542      1266    gsd-datetime
        ***** 2950      1266    deja-dup-monito
        ***** 1546      1266    gsd-housekeepin
        ***** 1548      1266    gsd-keyboard
        ***** 1550      1266    gsd-media-keys

``linux.pstree`` helps us to display the parent child relation of processes. 

Now to find the commands ran in bash shell. Lets use ``linux.bash``.

.. code-block:: shell-session

    $ python3 vol.py -f memory.vmem linux.bash 

        Volatility 3 Framework 2.0.3
        Progress:  100.00               Stacking attempts finished
        PID     Process CommandTime     Command

        1733    bash    2020-01-16 14:00:36.000000      sudo reboot
        1733    bash    2020-01-16 14:00:36.000000      AWAVH��
        1733    bash    2020-01-16 14:00:36.000000      sudo apt upgrade
        1733    bash    2020-01-16 14:00:36.000000      sudo apt upgrade
        1733    bash    2020-01-16 14:00:36.000000      sudo reboot
        1733    bash    2020-01-16 14:00:36.000000      sudo apt update
        1733    bash    2020-01-16 14:00:36.000000      sudo apt update
        1733    bash    2020-01-16 14:00:36.000000      sudo reboot
        1733    bash    2020-01-16 14:00:36.000000      sudo apt upgrade
        1733    bash    2020-01-16 14:00:36.000000      sudo apt update
        1733    bash    2020-01-16 14:00:36.000000      rub
        1733    bash    2020-01-16 14:00:36.000000      sudo apt upgrade
        1733    bash    2020-01-16 14:00:36.000000      uname -a
        1733    bash    2020-01-16 14:00:36.000000      uname -a
        1733    bash    2020-01-16 14:00:36.000000      sudo apt autoclean
        1733    bash    2020-01-16 14:00:36.000000      sudo reboot
        1733    bash    2020-01-16 14:00:36.000000      sudo apt upgrade
        1733    bash    2020-01-16 14:00:41.000000      chmod +x meterpreter
        1733    bash    2020-01-16 14:00:42.000000      sudo ./meterpreter
