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
framework, Volatility 3. The project was intended to address many of the
technical and performance challenges associated with the original
code base that became apparent over the previous 10 years. Another benefit
of the rewrite is that Volatility 3 could be released under a custom
license that was more aligned with the goals of the Volatility community,
the Volatility Contributors Public License (VCPL). See the LICENSE file for
more details.

Requirements
============

- Python 3.5.3 or later. http://www.python.org
- Pefile 2017.8.1 or later. https://pypi.org/project/pefile/

Optional Dependencies
=====================

- yara-python 3.8.0 or later. https://github.com/VirusTotal/yara-python
- capstone 3.0.0 or later. https://www.capstone-engine.org/download.html

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
'python -f <imagepath> windows.info’

   Example:

    $ python vol.py —f /home/user/samples/stuxnet.vmem windows.info

4. Run some other plugins. The -f or —-single-location is not strictly
required, but most plugins expect a single sample. Some also
require/accept other options.  Run "python vol.py <plugin> -h"
for more information on a particular command.

Licensing and Copyright
=======================

Copyright (C) 2007-2019 Volatility Foundation

All Rights Reserved

https://www.volatilityfoundation.org/license/vsl_v1.0

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
