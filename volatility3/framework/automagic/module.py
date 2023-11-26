# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import interfaces, constants, configuration


class KernelModule(interfaces.automagic.AutomagicInterface):
    """Finds ModuleRequirements and ensures their layer, symbols and offsets"""

    priority = 100

    def __call__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        requirement: interfaces.configuration.RequirementInterface,
        progress_callback: constants.ProgressCallback = None,
    ) -> None:
        new_config_path = interfaces.configuration.path_join(
            config_path, requirement.name
        )
        if not isinstance(requirement, configuration.requirements.ModuleRequirement):
            # Check subrequirements
            for req in requirement.requirements:
                self(
                    context,
                    new_config_path,
                    requirement.requirements[req],
                    progress_callback,
                )
            return None
        if not requirement.unsatisfied(context, config_path):
            return None
        # The requirement is unfulfilled and is a ModuleRequirement

        context.config[
            interfaces.configuration.path_join(new_config_path, "class")
        ] = "volatility3.framework.contexts.Module"

        for req in requirement.requirements:
            if (
                requirement.requirements[req].unsatisfied(context, new_config_path)
                and req != "offset"
            ):
                return None

        # We now just have the offset requirement, but the layer requirement has been fulfilled.
        # Unfortunately we don't know the layer name requirement's exact name

        for req in requirement.requirements:
            if isinstance(
                requirement.requirements[req],
                configuration.requirements.TranslationLayerRequirement,
            ):
                layer_kvo_config_path = interfaces.configuration.path_join(
                    new_config_path, req, "kernel_virtual_offset"
                )
                offset_config_path = interfaces.configuration.path_join(
                    new_config_path, "offset"
                )
                offset = context.config[layer_kvo_config_path]
                context.config[offset_config_path] = offset

        # Now construct the module based on the sub-requirements
        requirement.construct(context, config_path)
