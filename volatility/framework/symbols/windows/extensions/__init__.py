import collections.abc
import random
import string

from volatility.framework import interfaces
from volatility.framework import objects


# Keep these in a basic module, to prevent import cycles when symbol providers require them

class _ETHREAD(objects.Struct):
    def owning_process(self, kernel_layer = None):
        """Return the EPROCESS that owns this thread"""
        return self.ThreadsProcess.dereference(kernel_layer)


class _EPROCESS(objects.Struct):
    def add_process_layer(self, context, config_prefix = None, preferred_name = None):
        """Constructs a new layer based on the process's DirectoryTableBase"""

        if config_prefix is None:
            # TODO: Ensure collisions can't happen by verifying the config_prefix is empty
            random_prefix = ''.join(
                random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(8))
            config_prefix = interfaces.configuration.path_join("temporary", "_" + random_prefix)

        # Figure out a suitable name we can use for the new layer
        if preferred_name is None:
            preferred_name = context.memory.free_layer_name(
                prefix = self.vol.layer_name + "_PID" + str(self.UniqueProcessId) + "_")
        else:
            if preferred_name in context.memory:
                preferred_name = context.memory.free_layer_name(prefix = preferred_name)

        # Copy the parent's config and then make suitable changes
        parent_layer = context.memory[self.vol.layer_name]
        parent_config = parent_layer.build_configuration()
        parent_config['memory_layer'] = parent_layer.config['memory_layer']
        # Presumably for 64-bit systems, the DTB is defined as an array, rather than an unsigned long long
        if isinstance(self.Pcb.DirectoryTableBase, objects.Array):
            parent_config['page_map_offset'] = self.Pcb.DirectoryTableBase.cast("unsigned long long")
        else:
            parent_config['page_map_offset'] = self.Pcb.DirectoryTableBase
        parent_config['page_map_offset'] = parent_config['page_map_offset'] & (
            (1 << parent_layer.bits_per_register) - 1)

        # Set the new configuration and construct the layer
        config_path = interfaces.configuration.path_join(config_prefix, preferred_name)
        context.config.splice(config_path, parent_config)
        new_layer = parent_layer.__class__(context, config_path = config_path, name = preferred_name)

        # Add the constructed layer and return the name
        context.memory.add_layer(new_layer)
        return preferred_name


class _LIST_ENTRY(objects.Struct, collections.abc.Iterable):
    def to_list(self, symbol_type, member, forward = True, sentinel = True, layer = None):
        """Returns an iterator of the entries in the list"""

        if layer is None:
            layer = self.vol.layer_name

        relative_offset = self._context.symbol_space.get_type(symbol_type).relative_child_offset(member)

        direction = 'Blink'
        if forward:
            direction = 'Flink'
        link = getattr(self, direction).dereference()

        if not sentinel:
            yield self._context.object(symbol_type, layer, offset = self.vol.offset - relative_offset)

        seen = {self.vol.offset}
        while link.vol.offset not in seen:

            obj = self._context.object(symbol_type, layer, offset = link.vol.offset - relative_offset)
            yield obj

            seen.add(link.vol.offset)
            link = getattr(link, direction).dereference()

    def __iter__(self):
        return self.to_list(self.vol.parent.vol.type_name, self.vol.member_name)
