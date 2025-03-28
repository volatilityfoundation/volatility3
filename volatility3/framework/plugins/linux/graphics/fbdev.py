# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
import io

from dataclasses import dataclass
from typing import Type, List, Dict, Tuple
from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import (
    format_hints,
    TreeGrid,
    NotAvailableValue,
    UnreadableValue,
)
from volatility3.framework.objects import utility
from volatility3.framework.constants import architectures
from volatility3.framework.symbols import linux

# Image manipulation functions are kept in the plugin,
# to prevent a general exit on missing PIL (pillow) dependency.
try:
    from PIL import Image

    has_pil = True
except ImportError:
    has_pil = False

vollog = logging.getLogger(__name__)


@dataclass
class Framebuffer:
    """Framebuffer object internal representation. This is useful to unify a framebuffer with precalculated
    properties and pass it through functions conveniently."""

    id: str
    xres_virtual: int
    yres_virtual: int
    line_length: int
    bpp: int
    """Bits Per Pixel"""
    size: int
    color_fields: Dict[str, Tuple[int, int, int]]
    fb_info: interfaces.objects.ObjectInterface


class Fbdev(interfaces.plugins.PluginInterface):
    """Extract framebuffers from the fbdev graphics subsystem"""

    _version = (1, 0, 0)
    _required_framework_version = (2, 11, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=architectures.LINUX_ARCHS,
            ),
            requirements.VersionRequirement(
                name="linuxutils", component=linux.LinuxUtilities, version=(2, 2, 0)
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Dump framebuffers",
                default=False,
                optional=True,
            ),
        ]

    @classmethod
    def parse_fb_pixel_bitfields(
        cls, fb_var_screeninfo: interfaces.objects.ObjectInterface
    ) -> Dict[str, Tuple[int, int, int]]:
        """Organize a framebuffer pixel format into a dictionary.
        This is needed to know the position and bitlength of a color inside
        a pixel.

        Args:
            fb_var_screeninfo: a fb_var_screeninfo kernel object instance

        Returns:
            The color fields mappings

        Documentation:
            include/uapi/linux/fb.h:
                struct fb_bitfield {
                    __u32 offset;			/* beginning of bitfield	*/
                    __u32 length;			/* length of bitfield		*/
                    __u32 msb_right;		/* != 0 : Most significant bit is right */
                };
        """
        # Naturally order by RGBA
        color_mappings = [
            ("R", fb_var_screeninfo.red),
            ("G", fb_var_screeninfo.green),
            ("B", fb_var_screeninfo.blue),
            ("A", fb_var_screeninfo.transp),
        ]
        color_fields = {}
        for color_code, fb_bitfield in color_mappings:
            color_fields[color_code] = (
                int(fb_bitfield.offset),
                int(fb_bitfield.length),
                int(fb_bitfield.msb_right),
            )
        return color_fields

    @classmethod
    def convert_fb_raw_buffer_to_image(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_name: str,
        fb: Framebuffer,
    ):
        """Convert raw framebuffer pixels to an image.

        Args:
            fb: the relevant Framebuffer object

        Returns:
            A PIL Image object

        Documentation:
            include/uapi/linux/fb.h:
                /* Interpretation of offset for color fields: All offsets are from the right,
                * inside a "pixel" value, which is exactly 'bits_per_pixel' wide (means: you
                * can use the offset as right argument to <<). A pixel afterwards is a bit
                * stream and is written to video memory as that unmodified.
        """
        kernel = context.modules[kernel_name]
        kernel_layer = context.layers[kernel.layer_name]

        raw_pixels = io.BytesIO(kernel_layer.read(fb.fb_info.screen_base, fb.size))
        bytes_per_pixel = fb.bpp // 8
        image = Image.new("RGBA", (fb.xres_virtual, fb.yres_virtual))

        # This is not designed to be extremely fast (numpy isn't available),
        # but convenient and dynamic for any color field layout.
        for y in range(fb.yres_virtual):
            for x in range(fb.xres_virtual):
                raw_pixel = int.from_bytes(raw_pixels.read(bytes_per_pixel), "little")
                pixel = [0, 0, 0, 255]
                # The framebuffer is expected to have been correctly constructed,
                # especially by parse_fb_pixel_bitfields, to get the needed RGBA mappings.
                for i, color_code in enumerate(["R", "G", "B", "A"]):
                    offset, length, msb_right = fb.color_fields[color_code]
                    if length == 0:
                        continue
                    color_value = (raw_pixel >> offset) & (2**length - 1)
                    if msb_right:
                        # Reverse bit order
                        color_value = int(
                            "{:0{length}b}".format(color_value, length=length)[::-1], 2
                        )
                    pixel[i] = color_value
                image.putpixel((x, y), tuple(pixel))

        return image

    @classmethod
    def dump_fb(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_name: str,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
        fb: Framebuffer,
        convert_to_png_image: bool,
    ) -> str:
        """Dump a Framebuffer buffer to disk.

        Args:
            fb: the relevant Framebuffer object
            convert_to_image: a boolean specifying if the buffer should be converted to an image

        Returns:
            The filename of the dumped buffer.
        """
        kernel = context.modules[kernel_name]
        kernel_layer = context.layers[kernel.layer_name]
        id = "N-A" if isinstance(fb.id, NotAvailableValue) else fb.id
        base_filename = f"{id}_{fb.xres_virtual}x{fb.yres_virtual}_{fb.bpp}bpp"
        if convert_to_png_image:
            image_object = cls.convert_fb_raw_buffer_to_image(context, kernel_name, fb)
            raw_io_output = io.BytesIO()
            image_object.save(raw_io_output, "PNG")
            final_fb_buffer = raw_io_output.getvalue()
            filename = f"{base_filename}.png"
        else:
            final_fb_buffer = kernel_layer.read(fb.fb_info.screen_base, fb.size)
            filename = f"{base_filename}.raw"

        with open_method(filename) as f:
            f.write(final_fb_buffer)
            return f.preferred_filename

    @classmethod
    def parse_fb_info(
        cls,
        fb_info: interfaces.objects.ObjectInterface,
    ) -> Framebuffer:
        """Parse an fb_info struct
        Args:
            fb_info: an fb_info kernel object live instance

        Returns:
            A Framebuffer object

        Documentation:
            https://docs.kernel.org/fb/api.html:
                - struct fb_fix_screeninfo stores device independent unchangeable information about the frame buffer device and the current format.
                Those information can't be directly modified by applications, but can be changed by the driver when an application modifies the format.
                - struct fb_var_screeninfo stores device independent changeable information about a frame buffer device, its current format and video mode,
                as well as other miscellaneous parameters.
        """
        id = utility.array_to_string(fb_info.fix.id) or NotAvailableValue()
        color_fields = None

        # 0 = color, 1 = grayscale,	>1 = FOURCC
        if fb_info.var.grayscale in [0, 1]:
            color_fields = cls.parse_fb_pixel_bitfields(fb_info.var)

        # There a lot of tricky pixel formats used by drivers and vendors in include/uapi/linux/videodev2.h.
        # As Volatility3 is not a video format converter, it is best to play it safe and let the user parse
        # the raw data manually (with ffmpeg for example).
        elif fb_info.var.grayscale > 1:
            fourcc = linux.LinuxUtilities.convert_fourcc_code(fb_info.var.grayscale)
            warn_msg = f"""Framebuffer "{id}" uses a FOURCC pixel format "{fourcc}" that isn't natively supported.
You can try using ffmpeg to decode the raw buffer. Example usage:
"ffmpeg -pix_fmts" to list supported formats, then
"ffmpeg -f rawvideo -video_size {fb_info.var.xres_virtual}x{fb_info.var.yres_virtual} -i <FILENAME>.raw -pix_fmt <FORMAT> output.png"."""
            vollog.warning(warn_msg)

        # Prefer using the virtual resolution, instead of the visible one.
        # This prevents missing non-visible data stored in the framebuffer.
        fb = Framebuffer(
            id,
            xres_virtual=fb_info.var.xres_virtual,
            yres_virtual=fb_info.var.yres_virtual,
            line_length=fb_info.fix.line_length,
            bpp=fb_info.var.bits_per_pixel,
            size=fb_info.var.yres_virtual * fb_info.fix.line_length,
            color_fields=color_fields,
            fb_info=fb_info,
        )

        return fb

    def _generator(self):

        if not has_pil:
            vollog.error(
                "PIL (pillow) module is required to use this plugin. Please install it manually or through pyproject.toml."
            )
            return

        kernel_name = self.config["kernel"]
        kernel = self.context.modules[kernel_name]

        if not kernel.has_symbol("num_registered_fb"):
            vollog.error(
                '"num_registered_fb" symbol does not exist in the symbol table. This means you are either analyzing an unsupported kernel version,  your symbol table is corrupt, or the fbdev driver is compiled as a kernel module.'
            )
            return

        try:
            num_registered_fb = kernel.object_from_symbol("num_registered_fb")
        except exceptions.SymbolError:
            vollog.error(
                'Creating an object from "num_registered_fb" caused a symbol error. This is a sign that the symbol table is outdated. Please re-generate your symbol table using the latest dwarf2json'
            )
            return

        if num_registered_fb < 1:
            vollog.info("No registered framebuffer in the fbdev API.")
            return

        registered_fb = kernel.object_from_symbol("registered_fb")
        fb_info_list = utility.array_of_pointers(
            registered_fb,
            num_registered_fb,
            kernel.symbol_table_name + constants.BANG + "fb_info",
            self.context,
        )

        for fb_info in fb_info_list:
            fb = self.parse_fb_info(fb_info)
            file_output = "Disabled"
            if self.config["dump"]:
                try:
                    file_output = self.dump_fb(
                        self.context, kernel_name, self.open, fb, bool(fb.color_fields)
                    )
                    file_output = str(file_output)
                except exceptions.InvalidAddressException as excp:
                    vollog.error(
                        f'Layer {excp.layer_name} failed to read address {hex(excp.invalid_address)} when dumping framebuffer "{fb.id}".'
                    )
                    file_output = UnreadableValue()

            try:
                fb_device_name = utility.pointer_to_string(
                    fb.fb_info.dev.kobj.name, 256
                )
            except exceptions.InvalidAddressException:
                fb_device_name = NotAvailableValue()

            yield (
                0,
                (
                    format_hints.Hex(fb.fb_info.screen_base),
                    fb_device_name,
                    fb.id,
                    fb.size,
                    f"{fb.xres_virtual}x{fb.yres_virtual}",
                    fb.bpp,
                    "RUNNING" if fb.fb_info.state == 0 else "SUSPENDED",
                    file_output,
                ),
            )

    def run(self):
        columns = [
            ("Address", format_hints.Hex),
            ("Device", str),
            ("ID", str),
            ("Size", int),
            ("Virtual resolution", str),
            ("BPP", int),
            ("State", str),
            ("Filename", str),
        ]

        return TreeGrid(
            columns,
            self._generator(),
        )
