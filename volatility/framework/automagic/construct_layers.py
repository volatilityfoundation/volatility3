"""An automagic module to use configuration data to configure and then construct classes that fulfill the descendants
of a :class:`~volatility.framework.interfaces.configuration.ConfigurableInterface`."""

import logging

from volatility.framework import constants
from volatility.framework import interfaces

vollog = logging.getLogger(__name__)


class ConstructionMagic(interfaces.automagic.AutomagicInterface):
    """Class to run through the requirement tree of the :class:`~volatility.framework.interfaces.configuration.ConfigurableInterface`
    and from the bottom of the tree upwards, attempt to construct all
    :class:`~volatility.framework.interfaces.configuration.ConstructableRequirementInterface` based classes.

    :warning: This `automagic` should run first to allow existing configurations to have been constructed for use by later automagic
    """
    priority = 0

    def __call__(self, context, config_path, requirement, progress_callback = None, optional = False):
        if not requirement.validate(context, config_path):
            # Having called validate at the top level tells us both that we need to dig deeper
            # but also ensures that TranslationLayerRequirements have got the correct subrequirements if their class is populated

            success = True
            subreq_config_path = interfaces.configuration.path_join(config_path, requirement.name)
            for subreq in requirement.requirements.values():
                self(context, subreq_config_path, subreq, optional or subreq.optional)
                valid = subreq.validate(context, subreq_config_path)
                # We want to traverse optional paths, so don't check until we've tried to validate
                # We also don't want to emit a debug message when a parent is optional, hence the optional parameter
                if not valid and not (optional or subreq.optional):
                    vollog.log(constants.LOGLEVEL_V, "Failed on requirement: {}".format(subreq_config_path))
                    success = False
            if not success:
                return False
            elif isinstance(requirement, interfaces.configuration.ConstructableRequirementInterface):
                # We know all the subrequirements are filled, so let's populate
                requirement.construct(context, config_path)
        return True
