from urllib import parse

import volatility
from volatility.framework import interfaces
from volatility.framework.automagic import construct_layers
from volatility.framework.layers import physical


class LayerStacker(interfaces.automagic.AutomagicInterface):
    """Class that attempts to build up """
    # Most important automagic, must happen first!
    priority = 10
    page_map_offset = None
    location = None

    def __call__(self, context, config_path, requirement):
        """Runs the automagic over the configurable"""

        # Quick exit if we're not needed
        if requirement.validate(context, config_path):
            return

        # Bow out quickly if the UI hasn't provided a single_location
        if "automagic.general.single_location" not in context.config:
            return
        location = context.config["automagic.general.single_location"]
        self._check_type(location, str)
        self._check_type(requirement, interfaces.configuration.RequirementInterface)
        self.location = parse.urlparse(location)

        # Setup the local copy of the resource
        self.local_store = None
        if self.location.scheme == "file":
            self.local_store = self.location.path

        new_context = context.clone()
        current_layer_name = context.memory.free_layer_name("FileLayer")
        current_config_path = interfaces.configuration.path_join("automagic", "layer_stacker", "stack",
                                                                 current_layer_name)
        # This must be specific to get us started, setup the config and run
        new_context.config[interfaces.configuration.path_join(current_config_path, "filename")] = self.local_store
        new_context.add_layer(physical.FileLayer(new_context, current_config_path, current_layer_name))

        # Repeatedly apply "determine what this is" code and build as much up as possible
        stacked = True
        stacked_layers = [current_layer_name]
        stack_set = sorted(volatility.framework.class_subclasses(interfaces.automagic.StackerLayerInterface),
                           key = lambda x: x.stack_order)
        while stacked == True:
            stacked = False
            new_layer = None
            stacker_cls = None
            for stacker_cls in stack_set:
                stacker = stacker_cls()
                try:
                    new_layer = stacker.stack(new_context, current_layer_name)
                    if new_layer:
                        new_context.memory.add_layer(new_layer)
                        break
                except Exception as excp:
                    pass
            else:
                stacked = False
            if new_layer and stacker_cls:
                stacked_layers = [new_layer.name] + stacked_layers
                current_layer_name = new_layer.name
                stacked = True
                stack_set.remove(stacker_cls)

        if stacked_layers:

            result = self.find_suitable_requirements(stacked_layers, requirement, new_context, config_path)
            if result:
                path, layer = result
                # splice in the new configuration into the original context
                context.config.splice(path, new_context.memory[layer].build_configuration())
            # Call the construction magic now we may have new things to construct
            constructor = construct_layers.ConstructionMagic()
            constructor(context, config_path, requirement)

    def find_suitable_requirements(self, stacked_layers, requirement, context, config_path):
        child_config_path = interfaces.configuration.path_join(config_path, requirement.name)
        if isinstance(requirement, interfaces.configuration.TranslationLayerRequirement):
            if not requirement.validate(context, config_path):
                original_setting = context.config.get(child_config_path, None)
                for layer in stacked_layers:
                    context.config[child_config_path] = layer
                    if requirement.validate(context, config_path):
                        return child_config_path, layer
                else:
                    # Clean-up to restore the config
                    if original_setting:
                        context.config[child_config_path] = original_setting
                    else:
                        del context.config[child_config_path]
        for req_name, req in requirement.requirements.items():
            result = self.find_suitable_requirements(stacked_layers, req, context, child_config_path)
            if result:
                return result
