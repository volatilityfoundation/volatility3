from urllib import parse

import volatility
from volatility.framework import interfaces
from volatility.framework.layers import physical


class LayerStacker(interfaces.automagic.AutomagicInterface):
    """Class that attempts to build up """
    priority = 10

    def __call__(self, context, config_path, _):
        """Runs the automagic over the configurable"""
        # Bow out quickly if the UI hasn't provided a single_location
        if "ui.single_location" not in context.config:
            return
        location = context.config["ui.single_location"]
        self._check_type(location, str)
        self.location = parse.urlparse(location)

        # Setup the local copy of the resource
        self.local_store = None
        if self.location.scheme == "file":
            self.local_store = self.location.path

        new_context = context.clone()
        current_layer = context.memory.free_layer_name()
        # This must be specific to get us started
        new_context.add_layer(
            physical.FileLayer(new_context, interfaces.configuration.path_join("automagic_general", current_layer),
                               current_layer, self.local_store))

        # Repeatedly apply "determine what this is" code and build as much up as possible
        stacked = True
        stacked_layers = []
        stack_set = sorted(volatility.framework.class_subclasses(interfaces.automagic.StackerLayerInterface),
                           key = lambda x: x.stack_order)
        while stacked == True:
            stacked = False
            new_layer = None
            stacker_cls = None
            for stacker_cls in stack_set:
                stacker = stacker_cls()
                try:
                    new_layer = stacker.stack(new_context, current_layer)
                    break
                except Exception as excp:
                    pass
            else:
                stacked = False
            if new_layer and stacker_cls:
                stacked_layers = [new_layer] + stacked_layers
                current_layer = new_layer
                stacked = True
                stack_set.remove(stacker_cls)

        if stacked_layers:
            # Run through the layers we stacked and see if any of them will fit any of the requirements in the original context requirement Tree.
            # If they do take the highest one (furthest developed) and use that
            pass
