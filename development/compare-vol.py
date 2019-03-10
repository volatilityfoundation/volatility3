import csv
import hashlib
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class VolatilityImage:
    filepath: str = ""
    vol2_profile: str = ""
    vol2_time_imageinfo: int = None
    vol2_plugin_parameters: Dict[str, List[str]] = field(default_factory = dict)
    vol3_plugin_parameters: Dict[str, List[str]] = field(default_factory = dict)


@dataclass
class VolatilityPlugin:
    name: str = ""
    vol2_plugin_parameters: List[str] = field(default_factory = list)
    vol3_plugin_parameters: List[str] = field(default_factory = list)


class VolatilityTester:

    def __init__(self, images, plugins, output_dir, vol2_path: str = None, vol3_path: str = None):
        self.images = images
        self.plugins = plugins
        self.output_directory = output_dir
        self.volatility2_path = vol2_path or self.output_directory
        self.volatility3_path = vol3_path or self.output_directory
        self.csv_writer = None
        print("[?] Vol2 path", self.volatility2_path)
        print("[?] Vol3 path", self.volatility3_path)
        print("")

    def run_tests(self):
        with open("volatility-timings.csv", 'w') as csvfile:
            self.csv_writer = csv.writer(csvfile)
            self.csv_writer.writerow(
                ["Image Path", "Plugin Name", "Volatility 3", "Volatility 2", "Image Info", "Volatility 2 Total"])
            for image in self.images:
                for plugin in self.plugins:
                    self.run_test(plugin, image)

    def run_test(self, plugin: VolatilityPlugin, image: VolatilityImage):
        image_hash = hashlib.md5(bytes(image.filepath, "latin-1")).hexdigest()
        # Volatility 2 image info
        if not image.vol2_profile:
            print("[*] Testing volatility2 imageinfo with image {}".format(image.filepath))
            os.chdir(self.volatility2_path)
            cmd = ["python2", "-u", "vol.py", "-f", image.filepath, "imageinfo"]
            start_time = time.perf_counter()
            vol2_completed = subprocess.run(cmd, cwd = self.volatility2_path, capture_output = True)
            end_time = time.perf_counter()
            image.vol2_imageinfo_time = end_time - start_time
            print("    Tested  volatility2 imageinfo with image {}: {}".format(image.filepath, end_time - start_time))
            with open(os.path.join(self.output_directory, 'vol2_imageinfo_{}_stdout'.format(image_hash)), "wb") as f:
                f.write(vol2_completed.stdout)
            image.vol2_profile = re.search(b"Suggested Profile\(s\) : ([^,]+)", vol2_completed.stdout)[1]

        # Volatility 2 Test
        print("[*] Testing volatility2 {} with image {}".format(plugin.name, image.filepath))
        os.chdir(self.volatility2_path)
        cmd = ["python2", "-u", "vol.py", "-f", image.filepath, "--profile", image.vol2_profile
               ] + plugin.vol2_plugin_parameters + image.vol2_plugin_parameters.get(plugin.name, [])
        start_time = time.perf_counter()
        vol2_completed = subprocess.run(cmd, cwd = self.volatility2_path, capture_output = True)
        end_time = time.perf_counter()
        vol2_time = end_time - start_time
        print("    Tested  volatility2 {} with image {}: {}".format(plugin.name, image.filepath, vol2_time))
        with open(os.path.join(self.output_directory, 'vol2_{}_{}_stdout'.format(plugin.name, image_hash)), "wb") as f:
            f.write(vol2_completed.stdout)

        # Volatility 3 Test
        print("[*] Testing volatility3 {} with image {}".format(plugin.name, image.filepath))
        os.chdir(self.volatility3_path)
        cmd = [
            "python",
            "-u",
            "vol.py",
            "-f",
            image.filepath,
        ] + plugin.vol3_plugin_parameters + image.vol3_plugin_parameters.get(plugin.name, [])
        start_time = time.perf_counter()
        vol3_completed = subprocess.run(cmd, cwd = self.volatility3_path, capture_output = True)
        end_time = time.perf_counter()
        vol3_time = end_time - start_time
        print("    Tested  volatility3 {} with image {}: {}".format(plugin.name, image.filepath, vol3_time))
        with open(os.path.join(self.output_directory, 'vol3_{}_{}_stdout'.format(plugin.name, image_hash)), "wb") as f:
            f.write(vol3_completed.stdout)

        self.csv_writer.writerow([
            image.filepath, plugin.name, vol3_time, vol2_time, image.vol2_imageinfo_time,
            vol2_time + image.vol2_imageinfo_time
        ])


if __name__ == '__main__':
    vt = VolatilityTester([VolatilityImage(filepath = x) for x in sys.argv], [
        VolatilityPlugin(
            name = "pslist", vol2_plugin_parameters = ["pslist"], vol3_plugin_parameters = ["windows.pslist"]),
        VolatilityPlugin(
            name = "psscan", vol2_plugin_parameters = ["psscan"], vol3_plugin_parameters = ["windows.psscan"]),
        VolatilityPlugin(
            name = "hivelist", vol2_plugin_parameters = ["hivelist"], vol3_plugin_parameters = ["registry.hivelist"]),
        VolatilityPlugin(
            name = "printkey",
            vol2_plugin_parameters = ["printkey", "-K", "Classes"],
            vol3_plugin_parameters = ["registry.printkey", "--key", "Classes"])
    ], os.getcwd(), os.path.join(os.getcwd(), 'volatility'), os.path.join(os.getcwd(), 'volatility3'))
    vt.run_tests()
