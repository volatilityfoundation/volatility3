# This file was contributed to the Volatility Framework Version 3.
# Copyright (C) 2018 Volatility Foundation.
#
# THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors
# Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation,
# Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION
# OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED
# ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND ITS
# TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. "LICENSED
# WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A COPY OF THE
# LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" ACCOMPANYING THE
# CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT ACCOMPANY THIS FILE, A
# COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE FOLLOWING WEB SITE:
# https://www.volatilityfoundation.org/license/vcpl_v1.0
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
# specific language governing rights and limitations under the License.
#

from typing import Optional, Tuple

from volatility.framework import interfaces


class WindowsMetadata(interfaces.symbols.MetadataInterface):
    """Class to handle the metadata from a Windows symbol table"""

    @property
    def pe_version(self) -> Optional[Tuple]:
        build = self._json_data.get('pe', {}).get('build', None)
        revision = self._json_data.get('pe', {}).get('revision', None)
        minor = self._json_data.get('pe', {}).get('minor', None)
        major = self._json_data.get('pe', {}).get('major', None)
        if revision is None or minor is None or major is None:
            return None
        if build is None:
            return major, minor, revision
        return major, minor, revision, build

    @property
    def pe_version_string(self) -> Optional[str]:
        if self.pe_version is None:
            return None
        return ".".join(self.pe_version)

    @property
    def pdb_guid(self) -> Optional[str]:
        return self._json_data.get('pdb', {}).get('GUID', None)

    @property
    def pdb_age(self) -> Optional[int]:
        return self._json_data.get('pdb', {}).get('age', None)


class LinuxMetadata(interfaces.symbols.MetadataInterface):
    """Class to handle the etadata from a Linux symbol table"""
