__author__ = 'mike'

import volatility.framework.objects as objects


class _ETHREAD(objects.Struct):
    def owning_process(self, kernel_layer):
        """Return the EPROCESS that owns this thread"""
        return self.ThreadsProcess.dereference(kernel_layer)
