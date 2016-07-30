from volatility.framework.configuration import requirements
from volatility.framework.interfaces import automagic as automagic_interface, configuration as config_interface


class ConstructLayers(automagic_interface.AutomagicInterface):
    """Runs through the requirement tree and from the bottom up attempts to construct all TranslationLayerRequirements"""
    priority = 10

    def __call__(self, context, requirement, config_path):
        print("Processing", config_path, requirement.name)
        if not requirement.validate(context, config_path):
            # Having called validate at the top level tells us both that we need to dig deeper
            # but also ensures that TranslationLayerRequirements have got the correct subrequirements if their class is populated

            success = True
            for subreq in requirement.requirements.values():
                subreq_config_path = config_interface.path_join(config_path, requirement.name)
                self(context, subreq, subreq_config_path)
                valid = subreq.validate(context, subreq_config_path)
                # We want to traverse optional paths, so don't check until we've tried to validate
                if not valid and not subreq.optional:
                    success = False
            if not success:
                return False
            elif isinstance(requirement, requirements.TranslationLayerRequirement):
                # We know all the subrequirements are filled, so let's populate
                requirement.construct(context, config_path)
        return True
