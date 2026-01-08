macOS Tutorial
==============

This guide will give you a brief overview of how volatility3 works as well as a demonstration of several of the plugins available in the suite.

Acquiring memory
----------------

Volatility3 does not provide the ability to acquire memory. The example below is an open source tool. Other commercial tools are also available.

* `osxpmem <https://github.com/Velocidex/c-aff4/releases/download/3.2/osxpmem_3.2.zip>`_



Procedure to create symbol tables for macOS
--------------------------------------------

To create a symbol table please refer to :ref:`symbol-tables:Mac or Linux symbol tables`.

.. tip:: It may be possible to locate pre-made ISF files from the `download link <https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip>`_ ,
    which is built and maintained by `volatilityfoundation <https://www.volatilityfoundation.org/>`_.
    After creating the file or downloading it from the link, place the file under the directory ``volatility3/symbols/``.


Listing plugins
---------------

The following is a sample of the macOS plugins available for volatility3, it is not complete and more plugins may
be added.  For a complete reference, please see the volatility 3 :doc:`list of plugins <volatility3.plugins>`.
For plugin requests, please create an issue with a description of the requested plugin.

.. code-block:: shell-session

    $ python3 vol.py --help | grep -i mac. | head -n 4
        mac.bash.Bash       Recovers bash command history from memory.
        mac.check_syscall.Check_syscall
        mac.check_sysctl.Check_sysctl
        mac.check_trap_table.Check_trap_table

.. note:: Here the command is piped to grep and head to provide the start of the list of macOS plugins.


Using plugins
-------------

The following is the syntax to run the volatility CLI.

.. code-block:: shell-session

    $ python3 vol.py -f <path to memory image> <plugin_name> <plugin_option>


Example
-------

banners
~~~~~~~

In this example we will be using a memory dump from the Securinets CTF Quals 2019 Challenge called Contact_me.  We will limit the discussion to memory forensics with volatility 3 and not extend it to other parts of the challenge.
Thanks go to `stuxnet <https://github.com/stuxnet999/>`_ for providing this memory dump and `writeup <https://stuxnet999.github.io/securinets-ctf/2019/08/24/SecurinetsQuals2019-Contact-Me.html>`_.


.. code-block:: shell-session

    $ python3 vol.py -f contact_me banners.Banners
        
        Volatility 3 Framework 2.4.2

        Progress:  100.00               PDB scanning finished
        Offset  Banner
        
        0x4d2c7d0       Darwin Kernel Version 16.7.0: Thu Jun 15 17:36:27 PDT 2017; root:xnu-3789.70.16~2/RELEASE_X86_64
        0xb42b180       Darwin Kernel Version 16.7.0: Thu Jun 15 17:36:27 PDT 2017; root:xnu-3789.70.16~2/RELEASE_X86_64
        0xcda9100       Darwin Kernel Version 16.7.0: Thu Jun 15 17:36:27 PDT 2017; root:xnu-3789.70.16~2/RELEASE_X86_64
        0x1275e7d0      Darwin Kernel Version 16.7.0: Thu Jun 15 17:36:27 PDT 2017; root:xnu-3789.70.16~2/RELEASE_X86_64
        0x1284fba4      Darwin Kernel Version 16.7.0: Thu Jun 15 17:36:27 PDT 2017; root:xnu-3789.70.16~2/RELEASE_X86_64
        0x34ad0180      Darwin Kernel Version 16.7.0: Thu Jun 15 17:36:27 PDT 2017; root:xnu-3789.70.16~2/RELEASE_X86_64
        

The above command helps us to find the memory dump's Darwin kernel version. Now using the above banner we can search for the needed ISF file.
If an ISF file cannot be found then, follow the instructions on :ref:`getting-started-mac-tutorial:Procedure to create symbol tables for macOS`. After that, place the ISF file under the ``volatility3/symbols`` directory.

mac.pslist
~~~~~~~~~~

.. code-block:: shell-session

    $ python3 vol.py -f contact_me mac.pslist.PsList

        Volatility 3 Framework 2.4.2
        Progress:  100.00               Stacking attempts finished

        PID     PPID    COMM

        0       0       kernel_task
        1       0       launchd
        35      1       UserEventAgent
        38      1       kextd
        39      1       fseventsd
        37      1       uninstalld
        45      1       configd
        46      1       powerd
        52      1       logd
        58      1       warmd
        .....

``mac.pslist`` helps us to list the processes which are running, their PIDs and PPIDs.

mac.pstree
~~~~~~~~~~

.. code-block:: shell-session

    $ python3 vol.py -f contact_me mac.pstree.PsTree
        Volatility 3 Framework 2.4.2
        Progress:  100.00               Stacking attempts finished
        PID     PPID    COMM

        35      1       UserEventAgent
        38      1       kextd
        39      1       fseventsd
        37      1       uninstalld
        204     1       softwareupdated
        * 449   204     SoftwareUpdateCo
        337     1       system_installd
        * 455   337     update_dyld_shar

``mac.pstree`` helps us to display the parent-child relationships between processes.

mac.ifconfig
~~~~~~~~~~~~

.. code-block:: shell-session

    $ python3 vol.py -f contact_me mac.ifconfig.Ifconfig

        Volatility 3 Framework 2.4.2
        Progress:  100.00               Stacking attempts finished
        Interface       IP Address      Mac Address     Promiscuous

        lo0                     False
        lo0     127.0.0.1               False
        lo0     ::1             False
        lo0     fe80:1::1               False
        gif0                    False
        stf0                    False
        en0     00:0C:29:89:8B:F0       00:0C:29:89:8B:F0       False
        en0     fe80:4::10fb:c89d:217f:52ae     00:0C:29:89:8B:F0       False
        en0     192.168.140.128 00:0C:29:89:8B:F0       False
        utun0                   False
        utun0   fe80:5::2a95:bb15:87e3:977c             False
        
We can use the ``mac.ifconfig`` plugin to get information about the configuration of the network interfaces of the host under investigation.
