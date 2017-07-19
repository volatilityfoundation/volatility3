"""This module attempts to automatically stack layers.

This automagic module fulfills :class:`~volatility.framework.interfaces.configuration.TranslationLayerRequirement` that are not already fulfilled, by attempting to
stack as many layers on top of each other as possible.  The base/lowest layer is derived from the
"automagic.general.single_location" configuration path.  Layers are then attempting in likely height order, and
once a layer successfully stacks on top of the existing layers, it is removed from the possible choices list
(so no layer type can exist twice in the layer stack).
"""

import logging
from urllib import parse

import volatility
from volatility.framework import configuration, interfaces
from volatility.framework.automagic import construct_layers
from volatility.framework.configuration import requirements
from volatility.framework.layers import physical

vollog = logging.getLogger(__name__)


class LayerStacker(interfaces.automagic.AutomagicInterface):
    """Class that attempts to build up layers in a single stack

    This class mimics the volatility 2 style of stacking address spaces.  It builds up various layers based on
    separate :class:`~volatility.framework.interfaces.automagic.StackerLayerInterface` classes.  These classes are
    built up based on a `stack_order` class variable each has.

    This has a high priority to provide other automagic modules as complete a context/configuration tree as possible.
    Upon completion it will re-call the :class:`~volatility.framework.automagic.construct_layers.ConstructionMagic`,
    so that any stacked layers are actually constructed and added to the context.
    """
    # Most important automagic, must happen first!
    priority = 10
    page_map_offset = None

    def __call__(self, context, config_path, requirement, progress_callback = None):
        """Runs the automagic over the configurable"""

        # Quick exit if we're not needed
        if not requirement.unsatisfied(context, config_path):
            return

        # Bow out quickly if the UI hasn't provided a single_location
        unsatisfied = self.unsatisfied(self.context, self.config_path)
        if unsatisfied:
            vollog.info("Unable to run LayerStacker, unsatisfied requirement: {}".format(unsatisfied))
            return unsatisfied
        if 'single_location' not in self.config:
            vollog.info("Unable to run LayerStacker, single_location parameter not provided")
            return []
        location = self.config["single_location"]
        if not location:
            vollog.info("Unable to run LayerStacker, single_location parameter not provided")
            return []
        self._check_type(location, str)
        self._check_type(requirement, interfaces.configuration.RequirementInterface)
        location = parse.urlparse(location)

        # Setup the local copy of the resource
        self.local_store = None
        if location.scheme == "file":
            self.local_store = location.path

        new_context = context.clone()
        current_layer_name = context.memory.free_layer_name("FileLayer")
        current_config_path = interfaces.configuration.path_join(config_path, "stack", current_layer_name)
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
                    new_layer = stacker.stack(new_context, current_layer_name, progress_callback)
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

        vollog.debug("Stacked layers: {}".format(stacked_layers))

        if stacked_layers:

            result = self.find_suitable_requirements(stacked_layers, requirement, new_context, config_path)
            if result:
                path, layer = result
                # splice in the new configuration into the original context
                print("BEFORE", dict(context.config))
                context.config.merge(path, new_context.memory[layer].build_configuration())
                print("AFTER ", dict(context.config))
            # Call the construction magic now we may have new things to construct
            constructor = construct_layers.ConstructionMagic(context,
                                                             interfaces.configuration.path_join(self.config_path,
                                                                                                "ConstructionMagic"))
            constructor(context, config_path, requirement)

    def find_suitable_requirements(self, stacked_layers, requirement, context, config_path):
        """Looks for translation layer requirements and attempts to apply the stacked layers to it.  If it succeeds
        it returns the configuration path and layer name where the stacked nodes were spliced into the tree.

        :return: A tuple of a configuration path and layer name for the top of the stacked layers
        :rtype: (str, str)"""
        child_config_path = interfaces.configuration.path_join(config_path, requirement.name)
        if isinstance(requirement, interfaces.configuration.TranslationLayerRequirement):
            if requirement.unsatisfied(context, config_path):
                original_setting = context.config.get(child_config_path, None)
                for layer_name in stacked_layers:
                    context.config[child_config_path] = layer_name
                    if not requirement.unsatisfied(context, config_path):
                        return child_config_path, layer_name
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

    @classmethod
    def get_requirements(cls):
        # This is not optional for the stacker to run, so optional must be marked as False
        return [requirements.StringRequirement("single_location",
                                               description = "Specifies a base location on which to stack",
                                               optional = True)]
