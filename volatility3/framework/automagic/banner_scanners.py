from typing import Iterator, Optional, Tuple
from volatility3.framework.layers import scanners

VALID_BANNER_CHARSET = (
    b" #()+,;/-.0123456789:@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~"
)
BANNER_READ_SIZE = 0xFFF


class BannerScanner(scanners.RegExScanner):
    """Scanner for Linux and macOS kernel version strings."""

    BANNER_PATTERN = (
        rb"(Linux version|Darwin Kernel Version) [0-9]+\.[0-9]+\.[0-9]+[^\x00]+"
    )

    _version = (1, 0, 0)

    _required_framework_version = (2, 0, 0)

    def __init__(self) -> None:
        super().__init__(pattern=self.BANNER_PATTERN)

    def _get_valid_banner(self, offset: int) -> Optional[bytes]:
        """Gets the banner at a layer offset and validates it."""
        layer = self.context.layers[self.layer_name]
        data = layer.read(offset, BANNER_READ_SIZE, pad=True)
        data_index = data.find(b"\x00")
        if data_index <= 0:
            return None

        data = data[:data_index].strip()
        failed = any(char not in VALID_BANNER_CHARSET for char in data)
        if not failed:
            return data

        return None

    def __call__(self, data: bytes, data_offset: int) -> Iterator[Tuple[int, bytes]]:
        for off in super().__call__(data, data_offset):
            banner = self._get_valid_banner(off)
            if banner is not None:
                yield off, banner


class LinuxBannerScanner(BannerScanner):
    BANNER_PATTERN = rb"Linux version [0-9]+\.[0-9]+\.[0-9]+[^\x00]+"


class MacBannerScanner(BannerScanner):
    BANNER_PATTERN = rb"Darwin Kernel Version [0-9]+\.[0-9]+\.[0-9]+[^\x00]+"
