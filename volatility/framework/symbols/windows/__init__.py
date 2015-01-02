__author__ = 'mike'

import volatility.framework.objects as objects


class _ETHREAD(objects.Struct):
    def owning_process(self, kernel_layer = None):
        """Return the EPROCESS that owns this thread"""
        return self.ThreadsProcess.dereference(kernel_layer)


class _LIST_ENTRY(objects.Struct):
    def to_list(self, structure, member, forward = True, sentinel = True, layer = None):
        """Returns an iterator of the entries in the list"""

        if layer is None:
            layer = self._layer_name

        relative_offset = self._context.symbolspace.relative_child_offset(structure, member)

        direction = 'BLink'
        if forward:
            direction = 'FLink'
        link = getattr(self, direction).dereference()

        seen = set()
        while link.offset not in seen:

            object = self._context.Object(structure, layer, offset = link.offset)
            yield object

            seen.add(link.offset)
            link = getattr(link, direction).dereference()
