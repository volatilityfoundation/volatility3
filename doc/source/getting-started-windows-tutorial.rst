Windows Tutorial 
================

This guide provides a brief introduction to how volatility3 works as a demonstration of several of the plugins available in the suite.

Acquiring memory
----------------

Volatility does not provide the ability to acquire memory. 
Memory can be acquired using a number of tools, below are some examples but others exist:

* `WinPmem <https://github.com/Velocidex/WinPmem/releases/latest>`_
* `FTK Imager <https://accessdata.com/product-download/ftk-imager-version-4-5>`_

Listing Plugins
---------------

The following is a sample of the windows plugins available for volatility3, it is not complete and more more plugins may
be added.  For a complete reference, please see the volatility 3 :doc:`list of plugins <volatility3.plugins>`.
For plugin requests, please create an issue with a description of the requested plugin.

.. code-block:: shell-session

    $ python3 vol.py --help | grep windows | head -n 5
        windows.bigpools.BigPools
        windows.cmdline.CmdLine
        windows.crashinfo.Crashinfo
        windows.dlllist.DllList

.. note:: Here the the command is piped to grep and head in-order to provide the start of a list of the available windows plugins.

Using plugins
-------------

The following is the syntax to run the volatility CLI.

.. code-block:: shell-session

    $ python3 vol.py -f <path to memory image> plugin_name plugin_option


Example
-------

windows.pslist
~~~~~~~~~~~~~~

In this example we will be using a memory dump from the PragyanCTF'22.
We will limit the discussion to memory forensics with volatility 3 and not extend it to other parts of the challenges.

When using windows plugins in volatility 3, the required ISF file can often be generated from PDB files automatically
downloaded from Microsoft servers, and therefore does not require locating or adding specific ISF files to the volatility 3 symbols directory.

.. code-block:: shell-session

    $ python3 vol.py -f MemDump.DMP windows.pslist | head -n 10
        
        Volatility 3 Framework 2.0.1	PDB scanning finished                                

        PID	PPID	ImageFileName	Offset(V)       Threads	Handles	SessionId	Wow64	CreateTime	    ExitTime            File output

        4	0	    System	        0xfa8000cbc040	85	    492	    N/A	        False	2022-02-07      16:30:12.000000 	N/A	Disabled
        276	4	    smss.exe	    0xfa8001e04040	2	    29	    N/A	        False	2022-02-07      16:30:12.000000 	N/A	Disabled
        352	336	    csrss.exe	    0xfa8002110b30	9	    375	    0	        False	2022-02-07      16:30:13.000000 	N/A	Disabled
        404	336	    wininit.exe	    0xfa800219f060	3	    74	    0	        False	2022-02-07      16:30:13.000000 	N/A	Disabled
        412	396	    csrss.exe	    0xfa80021c5b30	9	    224	    1	        False	2022-02-07      16:30:13.000000 	N/A	Disabled
        468	396	    winlogon.exe    0xfa8002284060	5	    113	    1	        False	2022-02-07      16:30:14.000000 	N/A	Disabled

``windows.pslist`` helps list the processes running while the memory dump was taken.

windows.pstree
~~~~~~~~~~~~~~

.. code-block:: shell-session

    $ python3 vol.py -f MemDump.DMP windows.pstree | head -n 20
        Volatility 3 Framework 2.0.1	PDB scanning finished                                
        
        PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime
        
        4	0	System	0xfa8000cbc040	85	492	N/A	False	2022-02-07 16:30:12.000000 	N/A
        * 276	4	smss.exe	0xfa8001e04040	2	29	N/A	False	2022-02-07 16:30:12.000000 	N/A
        352	336	csrss.exe	0xfa8002110b30	9	375	0	False	2022-02-07 16:30:13.000000 	N/A
        404	336	wininit.exe	0xfa800219f060	3	74	0	False	2022-02-07 16:30:13.000000 	N/A
        * 504	404	services.exe	0xfa80022ccb30	7	190	0	False	2022-02-07 16:30:14.000000 	N/A
        ** 960	504	svchost.exe	0xfa8001c17b30	39	1003	0	False	2022-02-07 16:30:14.000000 	N/A
        ** 1216	504	svchost.exe	0xfa80026e0b30	18	311	0	False	2022-02-07 16:30:15.000000 	N/A
        ** 1312	504	svchost.exe	0xfa8002740380	19	287	0	False	2022-02-07 16:30:15.000000 	N/A
        ** 1984	504	taskhost.exe	0xfa8002eb1b30	8	129	1	False	2022-02-07 16:30:27.000000 	N/A
        ** 804	504	svchost.exe	0xfa80024ca5f0	20	450	0	False	2022-02-07 16:30:14.000000 	N/A
        *** 100	804	audiodg.exe	0xfa80025b4b30	6	131	0	False	2022-02-07 16:30:14.000000 	N/A
        ** 1568	504	SearchIndexer.	0xfa800254b480	12	616	0	False	2022-02-07 16:30:32.000000 	N/A
        ** 744	504	svchost.exe	0xfa8002477b30	8	265	0	False	2022-02-07 16:30:14.000000 	N/A
        ** 1096	504	svchost.exe	0xfa800260db30	14	357	0	False	2022-02-07 16:30:14.000000 	N/A
        ** 616	504	svchost.exe	0xfa8002b86ab0	13	314	0	False	2022-02-07 16:32:16.000000 	N/A
        ** 624	504	svchost.exe	0xfa8002410630	10	350	0	False	2022-02-07 16:30:14.000000 	N/A

``windows.pstree`` helps to display the parent child relationships between processes.

.. note:: Here the the command is piped to head in-order to provide smaller output, here listing only the first 20.

windows.hashdump
~~~~~~~~~~~~~~~~

.. code-block:: shell-session

    $ python3 vol.py -f MemDump.DMP windows.hashdump 
    Volatility 3 Framework 2.0.3
    Progress:  100.00		PDB scanning finished
    User	rid	lmhash	nthash

    Administrator	500	    aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
    Guest	        501	    aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
    Frank Reynolds	1000	aad3b435b51404eeaad3b435b51404ee	a88d1e18706d3aa676e01e5943d15911
    HomeGroupUser$	1002	aad3b435b51404eeaad3b435b51404ee	af10ecac6ea817d2bb56e3e5c33ce1cd
    Dennis	        1003	aad3b435b51404eeaad3b435b51404ee	cf96684bbc7877920adaa9663698bf54

``windows.hashdump`` helps to list the hashes of the users in the system.


    



