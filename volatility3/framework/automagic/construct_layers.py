# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""An automagic module to use configuration data to configure and then
construct classes that fulfill the descendants of a :class:`~volatility3.framewo
rk.interfaces.configuration.ConfigurableInterface`."""

import logging
import sys
from typing import List

from volatility3 import framework
from volatility3.framework import constants
from volatility3.framework import interfaces

vollog = logging.getLogger(__name__)


class ConstructionMagic(interfaces.automagic.AutomagicInterface):
    """Constructs underlying layers.

    Class to run through the requirement tree of the :class:`~volatility3.framework.interfaces.configuration.ConfigurableInterface`
    and from the bottom of the tree upwards, attempt to construct all
    :class:`~volatility3.framework.interfaces.configuration.ConstructableRequirementInterface` based classes.

    :warning: This `automagic` should run first to allow existing configurations to have been constructed for use by later automagic
    """

    priority = 0

    def __call__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        requirement: interfaces.configuration.RequirementInterface,
        progress_callback=None,
        optional=False,
    ) -> List[str]:
        # Make sure we import the layers, so they can reconstructed
        framework.import_files(sys.modules["volatility3.framework.layers"])

        result: List[str] = []
        if requirement.unsatisfied(context, config_path):
            # Having called validate at the top level tells us both that we need to dig deeper
            # but also ensures that TranslationLayerRequirements have got the correct subrequirements if their class is populated

            subreq_config_path = interfaces.configuration.path_join(
                config_path, requirement.name
            )
            for subreq in requirement.requirements.values():
                try:
                    self(
                        context,
                        subreq_config_path,
                        subreq,
                        optional=optional or subreq.optional,
                    )
                except Exception as e:
                    # We don't really care if this fails, it tends to mean the configuration isn't complete for that item
                    vollog.log(
                        constants.LOGLEVEL_VVVV, f"Construction Exception occurred: {e}"
                    )
                invalid = subreq.unsatisfied(context, subreq_config_path)
                # We want to traverse optional paths, so don't check until we've tried to validate
                # We also don't want to emit a debug message when a parent is optional, hence the optional parameter
                if invalid and not (optional or subreq.optional):
                    vollog.log(
                        constants.LOGLEVEL_V,
                        f"Failed on requirement: {subreq_config_path}",
                    )
                    result.append(
                        interfaces.configuration.path_join(
                            subreq_config_path, subreq.name
                        )
                    )
            if result:
                return result
            elif isinstance(
                requirement, interfaces.configuration.ConstructableRequirementInterface
            ):
                # We know all the subrequirements are filled, so let's populate
                requirement.construct(context, config_path)

        if progress_callback is not None:
            progress_callback(100, "Reconstruction finished")

        return []
