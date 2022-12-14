Linux Tutorial
==============

This guide will give you a brief overview of how volatility3 works as well as a demonstration of several of the plugins available in the suite.

Acquiring memory
----------------

Volatility3 does not provide the ability to acquire memory.  Below are some examples of tools that can be used to acquire memory, but more are available:

* `AVML - Acquire Volatile Memory for Linux <https://github.com/microsoft/avml>`_
* `LiME - Linux Memory Extract <https://github.com/504ensicsLabs/LiME>`_


Procedure to create symbol tables for linux
--------------------------------------------

To create a symbol table please refer to :ref:`symbol-tables:Mac or Linux symbol tables`.

.. tip:: It may be possible to locate pre-made ISF files from the `Linux ISF Server <https://isf-server.techanarchy.net/>`_ ,
    which is built and maintained by `kevthehermit <https://twitter.com/kevthehermit>`_.
    After creating the file or downloading it from the ISF server, place the file under the directory ``volatility3/symbols/linux``.
    If necessary create a linux directory under the symbols directory (this will become unnecessary in future versions).


Listing plugins
---------------

The following is a sample of the linux plugins available for volatility3, it is not complete and more more plugins may
be added.  For a complete reference, please see the volatility 3 :doc:`list of plugins <volatility3.plugins>`.
For plugin requests, please create an issue with a description of the requested plugin.

.. code-block:: shell-session

    $ python3 vol.py --help | grep -i linux. | head -n 5
        banners.Banners     Attempts to identify potential linux banners in an
        linux.bash.Bash     Recovers bash command history from memory.
        linux.check_afinfo.Check_afinfo
        linux.check_creds.Check_creds
        linux.check_idt.Check_idt

.. note:: Here the the command is piped to grep and head in-order to provide the start of the list of linux plugins.


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
Thanks go to `stuxnet <https://github.com/stuxnet999/>`_ for providing this memory dump and `writeup <https://stuxnet999.github.io/insomnihack/2020/09/17/Insomihack-getdents.html>`_.


.. code-block:: shell-session

    $ python3 vol.py -f memory.vmem banners
        
        Volatility 3 Framework 2.0.1

        Progress:  100.00               PDB scanning finished
        Offset  Banner

        0x141c1390      Linux version 4.15.0-42-generic (buildd@lgw01-amd64-023) (gcc version 7.3.0 (Ubuntu 7.3.0-16ubuntu3)) #45-Ubuntu SMP Thu Nov 15 19:32:57 UTC 2018 (Ubuntu 4.15.0-42.45-generic 4.15.18)
        0x63a00160      Linux version 4.15.0-72-generic (buildd@lcy01-amd64-026) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #81-Ubuntu SMP Tue Nov 26 12:20:02 UTC 2019 (Ubuntu 4.15.0-72.81-generic 4.15.18)
        0x6455c4d4      Linux version 4.15.0-72-generic (buildd@lcy01-amd64-026) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #81-Ubuntu SMP Tue Nov 26 12:20:02 UTC 2019 (Ubuntu 4.15.0-72.81-generic 4.15.18)
        0x6e1e055f      Linux version 4.15.0-72-generic (buildd@lcy01-amd64-026) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #81-Ubuntu SMP Tue Nov 26 12:20:02 UTC 2019 (Ubuntu 4.15.0-72.81-generic 4.15.18)
        0x7fde0010      Linux version 4.15.0-72-generic (buildd@lcy01-amd64-026) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #81-Ubuntu SMP Tue Nov 26 12:20:02 UTC 2019 (Ubuntu 4.15.0-72.81-generic 4.15.18)


The above command helps us to find the memory dump's kernel version and the distribution version. Now using the above banner we can search for the needed ISF file from the ISF server.
If ISF file cannot be found then, follow the instructions on :ref:`getting-started-linux-tutorial:Procedure to create symbol tables for linux`. After that, place the ISF file under the ``volatility3/symbols/linux`` directory.

.. tip:: Use the banner text which is most repeated to search from ISF Server.

linux.pslist
~~~~~~~~~~~~

.. code-block:: shell-session

    $ python3 vol.py -f memory.vmem linux.pslist

        Volatility 3 Framework 2.0.1    Stacking attempts finished

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

linux.pstree
~~~~~~~~~~~~

.. code-block:: shell-session

    $ python3 vol.py -f memory.vmem linux.pstree
        Volatility 3 Framework 2.0.1
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

``linux.pstree`` helps us to display the parent child relationships between processes.

linux.bash
~~~~~~~~~~

Now to find the commands that were run in the bash shell by using ``linux.bash``.

.. code-block:: shell-session

    $ python3 vol.py -f memory.vmem linux.bash 

        Volatility 3 Framework 2.0.1
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
