============================================================================
Volatility 3: The volatile memory extraction framework
============================================================================

Volatility is the world’s most widely used framework for extracting digital 
artifacts from volatile memory (RAM) samples. The extraction techniques are 
performed completely independent of the system being investigated but offer 
visibility into the runtime state of the system. The framework is intended 
to introduce people to the techniques and complexities associated with 
extracting digital artifacts from volatile memory samples and provide a 
platform for further work into this exciting area of research. 

In 2019, the Volatility Foundation released a complete rewrite of the 
framework, Volatility 3. The project was intended to address many of
technical and performance challenges associated with the original 
code base that became apparent over the previous 10 years. Another benefit
of the rewrite is that Volatility 3 could be released under a custom 
license that was more aligned with the goals of the Volatility community,
the Volatility Contributors Public License (VCPL). See the LICENSE file for 
more details.

Requirements
============

- Python 3.5.3 or later. http://www.python.org

Downloading Volatility
======================

The latest stable version of Volatility will always be the master 
branch of the GitHub repository. You can get the latest version of 
the code using the following command:

git clone https://github.com/volatilityfoundation/volatility3.git

Quick Start
===========

1. Clone the latest version of Volatility from GitHub:

    git clone https://github.com/volatilityfoundation/volatility3.git
   
2. To see available options, run "python vol.py -h"

3. To get more information on a Windows memory sample and to make sure 
Volatility supports that sample type, run 
'python -f file://<imagepath> windows.info’ 

   Example:
   
    $ python vol.py —f file:///home/user/samples/stuxnet.vmem 
windows.info

4. Run some other plugins. The -f or —-single-location is not strictly 
required, but most plugins expect a single sample. Some also 
require/accept other options.  Run "python vol.py <plugin> -h" 
for more information on a particular command.  
   
Licensing and Copyright
=======================

Copyright (C) 2007-2019 Volatility Foundation

All Rights Reserved

THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors 
Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation, 
Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION 
OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED 
ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND 
ITS TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. 
"LICENSED WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A 
COPY OF THE LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" 
ACCOMPANYING THE CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT 
ACCOMPANY THIS FILE, A COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE 
FOLLOWING WEB SITE:  

https://www.volatilityfoundation.org/license

Bugs and Support
================

If you think you've found a bug, please report it at:

    https://github.com/volatilityfoundation/volatility3/issues

In order to help us solve your issues as quickly as possible,
please include the following information when filing a bug:

* The version of Volatility you're using
* The operating system used to run Volatility
* The version of Python used to run Volatility
* The suspected operating system of the memory sample
* The complete command line you used to run Volatility

Contact
=======

For information or requests, contact:

Volatility Foundation

Web: http://www.volatilityfoundation.org
     http://volatility-labs.blogspot.com

Email: volatility (at) volatilityfoundation (dot) org

Twitter: @volatility 
