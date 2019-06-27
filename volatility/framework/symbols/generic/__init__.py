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

import random
import string
from typing import Union

from volatility.framework import objects, interfaces


class GenericIntelProcess(objects.Struct):

    def _add_process_layer(self,
                           context: interfaces.context.ContextInterface,
                           dtb: Union[int, interfaces.objects.ObjectInterface],
                           config_prefix: str = None,
                           preferred_name: str = None) -> str:
        """Constructs a new layer based on the process's DirectoryTableBase"""

        if config_prefix is None:
            # TODO: Ensure collisions can't happen by verifying the config_prefix is empty
            random_prefix = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits)
                                    for _ in range(8))
            config_prefix = interfaces.configuration.path_join("temporary", "_" + random_prefix)

        # Figure out a suitable name we can use for the new layer
        if preferred_name is None:
            preferred_name = context.layers.free_layer_name(prefix = self.vol.layer_name + "_Process_")
        else:
            if preferred_name in context.layers:
                preferred_name = context.layers.free_layer_name(prefix = preferred_name)

        # Copy the parent's config and then make suitable changes
        parent_layer = context.layers[self.vol.layer_name]
        parent_config = parent_layer.build_configuration()
        # It's an intel layer, because we hardwire the "memory_layer" config option
        # FIXME: this could be for other architectures if we don't hardwire this/these values
        parent_config['memory_layer'] = parent_layer.config['memory_layer']
        parent_config['page_map_offset'] = dtb

        # Set the new configuration and construct the layer
        config_path = interfaces.configuration.path_join(config_prefix, preferred_name)
        context.config.splice(config_path, parent_config)
        new_layer = parent_layer.__class__(context, config_path = config_path, name = preferred_name)

        # Add the constructed layer and return the name
        context.layers.add_layer(new_layer)
        return preferred_name
