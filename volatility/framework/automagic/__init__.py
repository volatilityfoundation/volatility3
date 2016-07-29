import sys

from volatility.framework import class_subclasses, import_files
from volatility.framework.configuration import MultiRequirement
from volatility.framework.interfaces import automagic as automagic_interface
from volatility.framework.interfaces.configuration import ConfigurableInterface


def automagic(context, configurable, config_path = ""):
    """Runs through all the appropriate automagic capabilities on the configurable

       This is where any automagic is allowed to run, and alter the context in order to satisfy/improve all requirements
    """
    import_files(sys.modules[__name__])
    if not isinstance(configurable, ConfigurableInterface) and not issubclass(configurable, ConfigurableInterface):
        raise TypeError("Automagic operates on configurables only")
    automagics = [clazz() for clazz in class_subclasses(automagic_interface.AutomagicInterface)]

    # TODO: Fix need for top level config element just because we're using a MultiRequirement to group the
    # configurable's config requirements
    configurable_class = configurable
    if isinstance(configurable, ConfigurableInterface):
        configurable_class = configurable.__class__
    requirement = MultiRequirement(name = configurable_class.__name__.lower())
    for req in configurable.get_requirements():
        requirement.add_requirement(req)

    for automagic in sorted(automagics, key = lambda x: x.priority):
        automagic(context, requirement, config_path)
