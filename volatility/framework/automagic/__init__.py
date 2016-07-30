import sys

from volatility.framework import class_subclasses, import_files
from volatility.framework.configuration import MultiRequirement
from volatility.framework.interfaces import automagic as automagic_interface
from volatility.framework.interfaces.configuration import ConfigurableInterface


def available():
    """Determine all the available automagic classes"""
    import_files(sys.modules[__name__])
    return sorted([clazz() for clazz in class_subclasses(automagic_interface.AutomagicInterface)],
                  key = lambda x: x.priority)


def run(automagics, context, configurable, config_path = ""):
    """Runs through the list of automagics in order, allowing them to make changes to the context

       This is where any automagic is allowed to run, and alter the context in order to satisfy/improve all requirements
    """
    if not isinstance(configurable, ConfigurableInterface) and not issubclass(configurable, ConfigurableInterface):
        raise TypeError("Automagic operates on configurables only")

    # TODO: Fix need for top level config element just because we're using a MultiRequirement to group the
    # configurable's config requirements
    configurable_class = configurable
    if isinstance(configurable, ConfigurableInterface):
        configurable_class = configurable.__class__
    requirement = MultiRequirement(name = configurable_class.__name__.lower())
    for req in configurable.get_requirements():
        requirement.add_requirement(req)

    for automagic in automagics:
        automagic(context, requirement, config_path)
