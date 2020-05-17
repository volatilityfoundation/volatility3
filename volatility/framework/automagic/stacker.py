# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""This module attempts to automatically stack layers.

This automagic module fulfills :class:`~volatility.framework.interfaces.configuration.TranslationLayerRequirement` that are not already fulfilled, by attempting to
stack as many layers on top of each other as possible.  The base/lowest layer is derived from the
"automagic.general.single_location" configuration path.  Layers are then attempting in likely height order, and
once a layer successfully stacks on top of the existing layers, it is removed from the possible choices list
(so no layer type can exist twice in the layer stack).
"""

import logging
import sys
import traceback
from typing import List, Optional, Tuple

from volatility import framework
from volatility.framework import interfaces, constants
from volatility.framework.automagic import construct_layers
from volatility.framework.configuration import requirements
from volatility.framework.layers import physical

vollog = logging.getLogger(__name__)


class LayerStacker(interfaces.automagic.AutomagicInterface):
    """Builds up layers in a single stack.

    This class mimics the volatility 2 style of stacking address spaces.  It builds up various layers based on
    separate :class:`~volatility.framework.interfaces.automagic.StackerLayerInterface` classes.  These classes are
    built up based on a `stack_order` class variable each has.

    This has a high priority to provide other automagic modules as complete a context/configuration tree as possible.
    Upon completion it will re-call the :class:`~volatility.framework.automagic.construct_layers.ConstructionMagic`,
    so that any stacked layers are actually constructed and added to the context.
    """
    priority = 9

    def __call__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 requirement: interfaces.configuration.RequirementInterface,
                 progress_callback: constants.ProgressCallback = None) -> Optional[List[str]]:
        """Runs the automagic over the configurable."""
        if not self.config or not self.config.get('single_location'):
            # "Successful" but no results
            return []

        vollog.warning("Outdated Interface: The LayerStacker interface has been deprecated for TranslationLayerStacker")
        # raise DeprecationWarning("The LayerStacker has been updated as TranslationLayerStacker")

        unsatisfied = self.unsatisfied(self.context, self.config_path)
        if unsatisfied:
            vollog.info("Unable to run LayerStacker, unsatisfied requirement: {}".format(unsatisfied))
            return list(unsatisfied)

        # Setup the local copy of the resource
        base_config_path = config_path.split(interfaces.configuration.CONFIG_SEPARATOR)
        tls_config_path = interfaces.configuration.path_join(*base_config_path, 'TranslationLayerStacker')
        single_location = self.config['single_location']
        current_layer_name = context.layers.free_layer_name("FileLayer")
        current_config_path = interfaces.configuration.path_join(config_path, "base_layer", current_layer_name)

        # This must be specific to get us started, setup the config and run
        context.config[interfaces.configuration.path_join(current_config_path, "location")] = single_location
        physical_layer = physical.FileLayer(context, current_config_path, current_layer_name)
        context.add_layer(physical_layer)

        # Setup and call the TranslationLayerStacker
        context.config[interfaces.configuration.path_join(tls_config_path, 'initial_layer')] = physical_layer.name
        stacker = TranslationLayerStacker(context, tls_config_path)
        stacker(context, config_path, requirement, progress_callback)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.URIRequirement("single_location",
                                        description = "Specifies the URI of an initial physical file on which to stack",
                                        optional = True)
        ]


class TranslationLayerStacker(interfaces.automagic.AutomagicInterface):
    """Builds up layers in a single stack.

    This class mimics the volatility 2 style of stacking address spaces.  It builds up various layers based on
    separate :class:`~volatility.framework.interfaces.automagic.StackerLayerInterface` classes.  These classes are
    built up based on a `stack_order` class variable each has.

    This has a high priority to provide other automagic modules as complete a context/configuration tree as possible.
    Upon completion it will re-call the :class:`~volatility.framework.automagic.construct_layers.ConstructionMagic`,
    so that any stacked layers are actually constructed and added to the context.
    """
    # Most important automagic, must happen first!
    priority = 10

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cached = None

    def __call__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 requirement: interfaces.configuration.RequirementInterface,
                 progress_callback: constants.ProgressCallback = None) -> Optional[List[str]]:
        """Runs the automagic over the configurable."""

        framework.import_files(sys.modules['volatility.framework.layers'])

        # Quick exit if we're not needed
        if not requirement.unsatisfied(context, config_path):
            return None

        # Bow out quickly if the UI hasn't provided a single_location
        unsatisfied = self.unsatisfied(self.context, self.config_path)
        if unsatisfied:
            vollog.info("Unable to run TranslationLayerStacker, unsatisfied requirement: {}".format(unsatisfied))
            return list(unsatisfied)

        # Search for suitable requirements
        self.stack(context, config_path, requirement, progress_callback)

        return None

    def stack(self, context: interfaces.context.ContextInterface, config_path: str,
              requirement: interfaces.configuration.RequirementInterface,
              progress_callback: constants.ProgressCallback) -> None:
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
            result = self.find_suitable_requirements(context, config_path, requirement, [top_layer_name])
            if result:
                appropriate_config_path, layer_name = result
                context.config.merge(appropriate_config_path, subconfig)
                context.config[appropriate_config_path] = top_layer_name
                return
            self._cached = None

        new_context = context.clone()
        current_layer_name = self.config.get('initial_layer', None)

        # Repeatedly apply "determine what this is" code and build as much up as possible
        stacked = True
        stacked_layers = [current_layer_name]
        stack_set = sorted(framework.class_subclasses(interfaces.automagic.StackerLayerInterface),
                           key = lambda x: x.stack_order)
        while stacked:
            stacked = False
            new_layer = None
            stacker_cls = None
            for stacker_cls in stack_set:
                stacker = stacker_cls()
                try:
                    vollog.log(constants.LOGLEVEL_VV, "Attempting to stack using {}".format(stacker_cls.__name__))
                    new_layer = stacker.stack(new_context, current_layer_name, progress_callback)
                    if new_layer:
                        new_context.layers.add_layer(new_layer)
                        vollog.log(constants.LOGLEVEL_VV,
                                   "Stacked {} using {}".format(new_layer.name, stacker_cls.__name__))
                        break
                except Exception as excp:
                    # Stacking exceptions are likely only of interest to developers, so the lowest level of logging
                    fulltrace = traceback.TracebackException.from_exception(excp).format(chain = True)
                    vollog.log(constants.LOGLEVEL_VVV, "Exception during stacking: {}".format(str(excp)))
                    vollog.log(constants.LOGLEVEL_VVVV, "\n".join(fulltrace))
            else:
                stacked = False
            if new_layer and stacker_cls:
                stacked_layers = [new_layer.name] + stacked_layers
                current_layer_name = new_layer.name
                stacked = True
                stack_set.remove(stacker_cls)

        if stacked_layers is not None:
            # Applies the stacked_layers to each requirement in the requirements list
            result = self.find_suitable_requirements(new_context, config_path, requirement, stacked_layers)
            if result:
                path, layer = result
                # splice in the new configuration into the original context
                context.config.merge(path, new_context.layers[layer].build_configuration())

                # Call the construction magic now we may have new things to construct
                constructor = construct_layers.ConstructionMagic(
                    context, interfaces.configuration.path_join(self.config_path, "ConstructionMagic"))
                constructor(context, config_path, requirement)

                # Stash the changed config items
                self._cached = context.config.get(path, None), context.config.branch(path)

        vollog.debug("Stacked layers: {}".format(stacked_layers))

    def find_suitable_requirements(self, context: interfaces.context.ContextInterface, config_path: str,
                                   requirement: interfaces.configuration.RequirementInterface,
                                   stacked_layers: List[str]) -> Optional[Tuple[str, str]]:
        """Looks for translation layer requirements and attempts to apply the
        stacked layers to it.  If it succeeds it returns the configuration path
        and layer name where the stacked nodes were spliced into the tree.

        Returns:
            A tuple of a configuration path and layer name for the top of the stacked layers
                or None if suitable requirements are not found
        """
        child_config_path = interfaces.configuration.path_join(config_path, requirement.name)
        if isinstance(requirement, requirements.TranslationLayerRequirement):
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
            else:
                return child_config_path, context.config.get(child_config_path, None)
        for req_name, req in requirement.requirements.items():
            result = self.find_suitable_requirements(context, child_config_path, req, stacked_layers)
            if result:
                return result
        return None

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.StringRequirement("initial_layer",
                                           description = "Specifies the name of a layer on which to stack",
                                           optional = True)
        ]
