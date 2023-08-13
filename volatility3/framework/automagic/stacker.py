# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""This module attempts to automatically stack layers.

This automagic module fulfills :class:`~volatility3.framework.interfaces.configuration.TranslationLayerRequirement` that are not already fulfilled, by attempting to
stack as many layers on top of each other as possible.  The base/lowest layer is derived from the
"automagic.general.single_location" configuration path.  Layers are then attempting in likely height order, and
once a layer successfully stacks on top of the existing layers, it is removed from the possible choices list
(so no layer type can exist twice in the layer stack).
"""

import logging
import sys
import traceback
from typing import List, Optional, Tuple, Type

from volatility3 import framework
from volatility3.framework import interfaces, constants
from volatility3.framework.automagic import construct_layers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import physical

vollog = logging.getLogger(__name__)


class LayerStacker(interfaces.automagic.AutomagicInterface):
    """Builds up layers in a single stack.

    This class mimics the volatility 2 style of stacking address spaces.  It builds up various layers based on
    separate :class:`~volatility3.framework.interfaces.automagic.StackerLayerInterface` classes.  These classes are
    built up based on a `stack_order` class variable each has.

    This has a high priority to provide other automagic modules as complete a context/configuration tree as possible.
    Upon completion it will re-call the :class:`~volatility3.framework.automagic.construct_layers.ConstructionMagic`,
    so that any stacked layers are actually constructed and added to the context.
    """

    # Most important automagic, must happen first!
    priority = 10

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._cached = None

    def __call__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        requirement: interfaces.configuration.RequirementInterface,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[List[str]]:
        """Runs the automagic over the configurable."""

        framework.import_files(sys.modules["volatility3.framework.layers"])

        # Quick exit if we're not needed
        if not requirement.unsatisfied(context, config_path):
            return None

        # Bow out quickly if the UI hasn't provided a single_location
        unsatisfied = self.unsatisfied(self.context, self.config_path)
        if unsatisfied:
            vollog.info(
                f"Unable to run LayerStacker, unsatisfied requirement: {unsatisfied}"
            )
            return list(unsatisfied)
        if not self.config or not self.config.get("single_location", None):
            raise ValueError(
                "Unable to run LayerStacker, single_location parameter not provided"
            )

        # Search for suitable requirements
        self.stack(context, config_path, requirement, progress_callback)

        if progress_callback is not None:
            progress_callback(100, "Stacking attempts finished")
        return None

    def stack(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        requirement: interfaces.configuration.RequirementInterface,
        progress_callback: constants.ProgressCallback,
    ) -> None:
        """Stacks the various layers and attaches these to a specific
        requirement.

        Args:
            context: Context on which to operate
            config_path: Configuration path under which to store stacking data
            requirement: Requirement that should have layers stacked on it
            progress_callback: Function to provide callback progress
        """
        # If we're cached, find Now we need to find where to apply the stack configuration
        if self._cached:
            top_layer_name, subconfig = self._cached
            result = self.find_suitable_requirements(
                context, config_path, requirement, [top_layer_name]
            )
            if result:
                appropriate_config_path, layer_name = result
                context.config.merge(appropriate_config_path, subconfig)
                context.config[appropriate_config_path] = top_layer_name
                return
            self._cached = None

        new_context = context.clone()
        location = self.config.get("single_location", None)

        # Setup the local copy of the resource
        current_layer_name = context.layers.free_layer_name("FileLayer")
        current_config_path = interfaces.configuration.path_join(
            config_path, "stack", current_layer_name
        )

        # This must be specific to get us started, setup the config and run
        new_context.config[
            interfaces.configuration.path_join(current_config_path, "location")
        ] = location
        physical_layer = physical.FileLayer(
            new_context, current_config_path, current_layer_name
        )
        new_context.add_layer(physical_layer)

        stacked_layers = self.stack_layer(
            new_context,
            current_layer_name,
            self.create_stackers_list(),
            progress_callback,
        )

        if stacked_layers is not None:
            # Applies the stacked_layers to each requirement in the requirements list
            result = self.find_suitable_requirements(
                new_context, config_path, requirement, stacked_layers
            )
            if result:
                path, layer = result
                # splice in the new configuration into the original context
                context.config.merge(
                    path, new_context.layers[layer].build_configuration()
                )

                # Call the construction magic now we may have new things to construct
                constructor = construct_layers.ConstructionMagic(
                    context,
                    interfaces.configuration.path_join(
                        self.config_path, "ConstructionMagic"
                    ),
                )
                constructor(context, config_path, requirement)

                # Stash the changed config items
                self._cached = context.config.get(path, None), context.config.branch(
                    path
                )
        vollog.debug(f"Stacked layers: {stacked_layers}")

    @classmethod
    def stack_layer(
        cls,
        context: interfaces.context.ContextInterface,
        initial_layer: str,
        stack_set: List[Type[interfaces.automagic.StackerLayerInterface]] = None,
        progress_callback: constants.ProgressCallback = None,
    ):
        """Stacks as many possible layers on top of the initial layer as can be done.

        WARNING: This modifies the context provided and may pollute it with unnecessary layers
        Recommended use is to:
        1. Pass in context.clone() instead of context
        2. When provided the layer list, choose the desired layer
        3. Build the configuration using layer.build_configuration()
        4. Merge the configuration into the original context with context.config.merge()
        5. Call Construction magic to reconstruct the layers from just the configuration

        Args:
            context: The context on which to operate
            initial_layer: The name of the initial layer within the context
            stack_set: A list of StackerLayerInterface objects in the order they should be stacked
            progress_callback: A function to report progress during the process

        Returns:
            A list of layer names that exist in the provided context, stacked in order (highest to lowest)
        """
        # Repeatedly apply "determine what this is" code and build as much up as possible
        stacked = True
        stacked_layers = [initial_layer]
        if stack_set is None:
            stack_set = list(
                framework.class_subclasses(interfaces.automagic.StackerLayerInterface)
            )

        for stacker_item in stack_set:
            if not issubclass(stacker_item, interfaces.automagic.StackerLayerInterface):
                raise TypeError(
                    f"Stacker {stacker_item.__name__} is not a descendent of StackerLayerInterface"
                )

        while stacked:
            stacked = False
            new_layer = None
            stacker_cls = None
            for stacker_cls in stack_set:
                stacker = stacker_cls()
                try:
                    vollog.log(
                        constants.LOGLEVEL_VV,
                        f"Attempting to stack using {stacker_cls.__name__}",
                    )
                    new_layer = stacker.stack(context, initial_layer, progress_callback)
                    if new_layer:
                        context.layers.add_layer(new_layer)
                        vollog.log(
                            constants.LOGLEVEL_VV,
                            f"Stacked {new_layer.name} using {stacker_cls.__name__}",
                        )
                        break
                except Exception as excp:
                    # Stacking exceptions are likely only of interest to developers, so the lowest level of logging
                    fulltrace = traceback.TracebackException.from_exception(
                        excp
                    ).format(chain=True)
                    vollog.log(
                        constants.LOGLEVEL_VVV,
                        f"Exception during stacking: {str(excp)}",
                    )
                    vollog.log(constants.LOGLEVEL_VVVV, "\n".join(fulltrace))
            else:
                stacked = False
            if new_layer and stacker_cls:
                stacked_layers = [new_layer.name] + stacked_layers
                initial_layer = new_layer.name
                stacked = True
                stack_set.remove(stacker_cls)
        return stacked_layers

    def create_stackers_list(
        self,
    ) -> List[Type[interfaces.automagic.StackerLayerInterface]]:
        """Creates the list of stackers to use based on the config option"""
        stack_set = sorted(
            framework.class_subclasses(interfaces.automagic.StackerLayerInterface),
            key=lambda x: x.stack_order,
        )
        stacker_list = self.config.get("stackers", [])
        if len(stacker_list):
            result = []
            for stacker in stack_set:
                if stacker.__name__ in stacker_list:
                    result.append(stacker)
            stack_set = result
        return stack_set

    @classmethod
    def find_suitable_requirements(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        requirement: interfaces.configuration.RequirementInterface,
        stacked_layers: List[str],
    ) -> Optional[Tuple[str, str]]:
        """Looks for translation layer requirements and attempts to apply the
        stacked layers to it.  If it succeeds it returns the configuration path
        and layer name where the stacked nodes were spliced into the tree.

        Returns:
            A tuple of a configuration path and layer name for the top of the stacked layers
                or None if suitable requirements are not found
        """
        child_config_path = interfaces.configuration.path_join(
            config_path, requirement.name
        )
        if isinstance(requirement, requirements.TranslationLayerRequirement):
            if requirement.unsatisfied(context, config_path):
                original_setting = context.config.get(child_config_path, None)
                for layer_name in stacked_layers:
                    context.config[child_config_path] = layer_name
                    if not requirement.unsatisfied(context, config_path):
                        return child_config_path, layer_name
                # Clean-up to restore the config
                if original_setting:
                    context.config[child_config_path] = original_setting
                else:
                    del context.config[child_config_path]
            else:
                return child_config_path, context.config.get(child_config_path, None)
        for req_name, req in requirement.requirements.items():
            result = cls.find_suitable_requirements(
                context, child_config_path, req, stacked_layers
            )
            if result:
                return result
        return None

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # This is not optional for the stacker to run, so optional must be marked as False
        return [
            requirements.URIRequirement(
                name="single_location",
                description="Specifies a base location on which to stack",
                optional=True,
            ),
            requirements.ListRequirement(
                name="stackers", description="List of stackers", optional=True
            ),
        ]


def choose_os_stackers(plugin: Type[interfaces.plugins.PluginInterface]) -> List[str]:
    """Identifies the stackers that should be run, based on the plugin (and thus os) provided"""
    plugin_first_level = plugin.__module__.split(".")[2]

    # Ensure all stackers are loaded
    framework.import_files(sys.modules["volatility3.framework.layers"])

    result = []
    for stacker in sorted(
        framework.class_subclasses(interfaces.automagic.StackerLayerInterface),
        key=lambda x: x.stack_order,
    ):
        if plugin_first_level in stacker.exclusion_list:
            continue
        result.append(stacker.__name__)
    return result
