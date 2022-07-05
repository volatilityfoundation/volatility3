Windows Tutorial 
================

This guide gives you a brief introduction to how volatility3 works and some demonstration on suite of plugins available from

Acquiring memory
----------------

Volatility does not provide the ability to acquire memory. In this tutorial we will see how we can use  `WinPmem <https://github.com/Velocidex/WinPmem/releases/latest>`_ for this purpose.

Listing Plugins
---------------

.. code-block:: shell-session

    $ python3 vol.py --help | grep windows | head -n 5
        windows.bigpools.BigPools
        windows.cmdline.CmdLine
        windows.crashinfo.Crashinfo
        windows.dlllist.DllList
                            Lists the loaded modules in a particular windows

Using plugins
-------------

The following is the syntax to run volatility tool.

.. code-block:: shell-session

    $ python3 vol.py -f <path to memory image> plugin_name plugin_option


Example
-------

Example 1
~~~~~~~~~

In this example we will be using memory dump from PragyanCTF'22. The dump is available `here <https://drive.google.com/file/d/1VPIdqIDFkOi3zGET2g00s1y-OeWOUqyi/view?usp=sharing>`_.
We will limit the discussion to memory forensics with volatility3 and not extend to other parts of the challenges. 

In windows memory forensics using volatility3, most of the times we do not require creating a ISF file. 

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

``windows.pslist`` helps us list the processes running while the memory dump was taken.

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

``windows.pstree`` helps us to display the parent child relation of processes.

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

``windows.hashdump`` helps us to list the hashes of the users in the system.


    



