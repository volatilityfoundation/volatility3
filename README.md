# Volatility 3: The volatile memory extraction framework

Volatility is the world’s most widely used framework for extracting digital <br>
artifacts from volatile memory (RAM) samples. The extraction techniques are <br>
performed completely independent of the system being investigated but offer <br>
visibility into the runtime state of the system. The framework is intended <br>
to introduce people to the techniques and complexities associated with <br>
extracting digital artifacts from volatile memory samples and provide a <br>
platform for further work into this exciting area of research. <br>
<br>
In 2019, the Volatility Foundation released a complete rewrite of the <br>
framework, Volatility 3. The project was intended to address many of the <br>
technical and performance challenges associated with the original <br>
code base that became apparent over the previous 10 years. Another benefit <br>
of the rewrite is that Volatility 3 could be released under a custom <br>
license that was more aligned with the goals of the Volatility community, <br>
the Volatility Software License (VSL). See the LICENSE file for more details. <br>

## Requirements

- Python 3.5.3 or later. http://www.python.org
- Pefile 2017.8.1 or later. https://pypi.org/project/pefile/

## Optional Dependencies

- yara-python 3.8.0 or later. https://github.com/VirusTotal/yara-python
- capstone 3.0.0 or later. https://www.capstone-engine.org/download.html

## Downloading Volatility

The latest stable version of Volatility will always be the master <br>
branch of the GitHub repository. You can get the latest version of <br>
the code using the following command: <br>

git clone https://github.com/volatilityfoundation/volatility3.git

## Quick Start

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

## Symbol Tables

Symbol table packs for the various operating systems are available for download at: <br>

https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip <br>
https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip <br>
https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip <br>

Symbol tables zip files must be placed, as named, into the volatility/symbols <br>
directory (or just the symbols directory next to the executable file). <br>
Window symbols that cannot be found will be queried, downloaded, generated and <br>
cached.  Mac and Linux symbol tables must be manually produced by a tool such <br>
as dwarf2json. <br>

Please note: These are representative and are complete up to the point of <br>
creation for windows and mac.  Due to the ease of compiling linux kernels and <br>
the inability to uniquely distinguish them, an exhaustive set of linux symbol <br>
tables cannot easily be supplied. <br>

## Documentation

The framework is documented through doc strings and can be built using sphinx. <br>

The latest generated copy of the documentation can be found at: <br>
https://volatility3.readthedocs.io/en/latest/ <br>

## Licensing and Copyright

Copyright (C) 2007-2019 Volatility Foundation

All Rights Reserved

https://www.volatilityfoundation.org/license/vsl-v1.0

## Bugs and Support

If you think you've found a bug, please report it at:

    https://github.com/volatilityfoundation/volatility3/issues

In order to help us solve your issues as quickly as possible,
please include the following information when filing a bug:

* The version of Volatility you're using
* The operating system used to run Volatility
* The version of Python used to run Volatility
* The suspected operating system of the memory sample
* The complete command line you used to run Volatility

For community support, please join us on slack:

https://www.volatilityfoundation.org/slack

## Contact

For information or requests, contact:

Volatility Foundation

Web: http://www.volatilityfoundation.org <br>
     http://volatility-labs.blogspot.com

Email: volatility (at) volatilityfoundation (dot) org

Twitter: @volatility
