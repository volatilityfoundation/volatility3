Linux Tutorial
==============

This guide gives you a brief introduction to how volatility3 works and some demonstration on suite of plugins available from

Acquiring memory
----------------

Volatility does not provide the ability to acquire memory. In this tutorial we will see how we can use  `Lime <https://github.com/504ensicslabs/lime>`_ for this purpose. 
It supports 32 and 64 bit captures from native Intel hardware as well as virtual machine guests. 
It also supports capture from Android devices. See below for example commands building and running LiME:

.. code-block:: shell-session

    $ tar -xvzf lime-forensics-1.1-r14.tar.gz 
    $ cd lime-forensics-1.1-r14/src
    $ make
    ....
      CC [M]  /home/mhl/Downloads/src/tcp.o
      CC [M]  /home/mhl/Downloads/src/disk.o
    ....
    $ sudo insmod lime-3.2.0-23-generic.ko "path=/home/mhl/ubuntu.lime format=lime"
    $ ls -alh /home/mhl/ubuntu.lime 
    -r--r--r-- 1 root root 2.0G Aug 17 19:37 /home/mhl/ubuntu.lime

Procedure to create symbol tables for linux
--------------------------------------------

To create a symbol table please refer this :ref:`symbol-tables:Mac or Linux symbol tables`.
We can also find some ISF files from `Linux ISF Server <https://isf-server.techanarchy.net/>`_ ,  which is built and maintained by `kevthehermit <https://twitter.com/kevthehermit>`_.
After creating the file or downloading the file from the ISF server, please place the file under the directory ``volatility3/symbols/linux``. Make a directory linux under symbols.


Listing plugins
---------------

Following are the list of linux plugins available for volatility3. More plugins will be available on future releases.
For plugin requests, Please create an issue with description of the plugin.

.. code-block:: shell-session

    $ vol3 --help | grep -i linux. | head -n 5
        banners.Banners     Attempts to identify potential linux banners in an
        linux.bash.Bash     Recovers bash command history from memory.
        linux.check_afinfo.Check_afinfo
        linux.check_creds.Check_creds
        linux.check_idt.Check_idt


Using plugins
-------------

The following is the syntax to run volatility tool.

.. code-block:: shell-session

    $ python3 vol.py -f <path to memory image> plugin_name plugin_option





