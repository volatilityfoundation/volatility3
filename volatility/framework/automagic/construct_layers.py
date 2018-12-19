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
"""An automagic module to use configuration data to configure and then construct classes that fulfill the descendants
of a :class:`~volatility.framework.interfaces.configuration.ConfigurableInterface`."""

import logging
from typing import List

from volatility.framework import constants
from volatility.framework import interfaces

vollog = logging.getLogger(__name__)


class ConstructionMagic(interfaces.automagic.AutomagicInterface):
    """Constructs underlying layers

    Class to run through the requirement tree of the :class:`~volatility.framework.interfaces.configuration.ConfigurableInterface`
    and from the bottom of the tree upwards, attempt to construct all
    :class:`~volatility.framework.interfaces.configuration.ConstructableRequirementInterface` based classes.

    :warning: This `automagic` should run first to allow existing configurations to have been constructed for use by later automagic
    """
    priority = 0

    def __call__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 requirement: interfaces.configuration.RequirementInterface,
                 progress_callback = None,
                 optional = False) -> List[str]:
        result = []  # type: List[str]
        if requirement.unsatisfied(context, config_path):
            # Having called validate at the top level tells us both that we need to dig deeper
            # but also ensures that TranslationLayerRequirements have got the correct subrequirements if their class is populated

            subreq_config_path = interfaces.configuration.path_join(config_path, requirement.name)
            for subreq in requirement.requirements.values():
                try:
                    self(context, subreq_config_path, subreq, optional or subreq.optional)
                except Exception as e:
                    # We don't really care if this fails, it tends to mean the configuration isn't complete for that item
                    vollog.log(constants.LOGLEVEL_VVVV, "Construction Exception occurred: {}".format(e))
                invalid = subreq.unsatisfied(context, subreq_config_path)
                # We want to traverse optional paths, so don't check until we've tried to validate
                # We also don't want to emit a debug message when a parent is optional, hence the optional parameter
                if invalid and not (optional or subreq.optional):
                    vollog.log(constants.LOGLEVEL_V, "Failed on requirement: {}".format(subreq_config_path))
                    result.append(interfaces.configuration.path_join(subreq_config_path, subreq.name))
            if result:
                return result
            elif isinstance(requirement, interfaces.configuration.ConstructableRequirementInterface):
                # We know all the subrequirements are filled, so let's populate
                requirement.construct(context, config_path)
        return []
