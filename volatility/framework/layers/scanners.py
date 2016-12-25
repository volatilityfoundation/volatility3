from volatility.framework.interfaces import layers


class BytesScanner(layers.ScannerInterface):
    thread_safe = True

    def __init__(self, needle):
        super().__init__()
        self.needle = self._check_type(needle, bytes)

    def __call__(self, data, data_offset):
        """Runs through the data looking for the needle, and yields all offsets where the needle is found
        """
        find_pos = data.find(self.needle)
        while find_pos >= 0:
            yield find_pos + data_offset
            find_pos = data.find(self.needle, find_pos + 1)
