# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import random
import string
import datetime
from typing import Union

from volatility3.framework import objects, interfaces


class GenericProcess(objects.StructType):
    """A Generic Process class which is not designed to be used directly but provide a base to be used elsewhere."""

    def get_pid(self) -> int:
        """get_pid should return the pid of the process"""
        raise NotImplementedError(
            "The GenericProcess base class has no get_pid method defined"
        )

    def get_parent_pid(self) -> int:
        """get_parent_pid should return the pid of the parent process"""
        raise NotImplementedError(
            "The GenericProcess base class has no get_parent_pid method defined"
        )

    def get_name(self) -> str:
        """get_name should return the friendly name of the process"""
        raise NotImplementedError(
            "The GenericProcess base class has no get_name method defined"
        )

    def get_create_time(self) -> datetime.datetime:
        """get_create_time should return the time the process was created/started"""
        raise NotImplementedError(
            "The GenericProcess base class has no get_start_time method defined"
        )

    def get_exit_time(self) -> datetime.datetime:
        """get_exit_time should return the time the process exited/finished"""
        raise NotImplementedError(
            "The GenericProcess base class has no get_exit_time method defined"
        )


class GenericIntelProcess(GenericProcess):
    def _add_process_layer(
        self,
        context: interfaces.context.ContextInterface,
        dtb: Union[int, interfaces.objects.ObjectInterface],
        config_prefix: str = None,
        preferred_name: str = None,
    ) -> str:
        """Constructs a new layer based on the process's DirectoryTableBase."""

        if config_prefix is None:
            # TODO: Ensure collisions can't happen by verifying the config_prefix is empty
            random_prefix = "".join(
                random.SystemRandom().choice(string.ascii_uppercase + string.digits)
                for _ in range(8)
            )
            config_prefix = interfaces.configuration.path_join(
                "temporary", "_" + random_prefix
            )

        # Figure out a suitable name we can use for the new layer
        if preferred_name is None:
            preferred_name = context.layers.free_layer_name(
                prefix=self.vol.layer_name + "_Process"
            )
        else:
            if preferred_name in context.layers:
                preferred_name = context.layers.free_layer_name(prefix=preferred_name)

        # Copy the parent's config and then make suitable changes
        parent_layer = context.layers[self.vol.layer_name]
        parent_config = parent_layer.build_configuration()
        # It's an intel layer, because we hardwire the "memory_layer" config option
        # FIXME: this could be for other architectures if we don't hardwire this/these values
        parent_config["memory_layer"] = parent_layer.config["memory_layer"]
        parent_config["page_map_offset"] = dtb

        # Set the new configuration and construct the layer
        config_path = interfaces.configuration.path_join(config_prefix, preferred_name)
        context.config.splice(config_path, parent_config)
        new_layer = parent_layer.__class__(
            context, config_path=config_path, name=preferred_name
        )

        # Add the constructed layer and return the name
        context.layers.add_layer(new_layer)
        return preferred_name
