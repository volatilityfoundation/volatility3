import collections.abc

from volatility.framework import objects

__author__ = 'mike'


class _ETHREAD(objects.Struct):
    def owning_process(self, kernel_layer = None):
        """Return the EPROCESS that owns this thread"""
        return self.ThreadsProcess.dereference(kernel_layer)


class _LIST_ENTRY(objects.Struct, collections.abc.Iterable):
    def to_list(self, structure, member, forward = True, sentinel = True, layer = None):
        """Returns an iterator of the entries in the list"""

        if layer is None:
            layer = self.vol.layer_name

        relative_offset = self._context.symbol_space.get_structure(structure).relative_child_offset(member)

        direction = 'Blink'
        if forward:
            direction = 'Flink'
        link = getattr(self, direction).dereference()

        if not sentinel:
            yield self._context.object(structure, layer, offset = self.vol.offset - relative_offset)

        seen = {self.vol.offset}
        while link.vol.offset not in seen:

            obj = self._context.object(structure, layer, offset = link.vol.offset - relative_offset)
            yield obj

            seen.add(link.vol.offset)
            link = getattr(link, direction).dereference()

    def __iter__(self):
        return self.to_list(self.vol.parent.vol.structure_name, self.vol.member_name)
