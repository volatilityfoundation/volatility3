import argparse
import csv
import hashlib
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class VolatilityImage:
    filepath: str = ""
    vol2_profile: str = ""
    vol2_imageinfo_time: float = None
    vol2_plugin_parameters: Dict[str, List[str]] = field(default_factory = dict)
    vol3_plugin_parameters: Dict[str, List[str]] = field(default_factory = dict)
    rekall_plugin_parameters: Dict[str, List[str]] = field(default_factory = dict)


@dataclass
class VolatilityPlugin:
    name: str = ""
    vol2_plugin_parameters: List[str] = field(default_factory = list)
    vol3_plugin_parameters: List[str] = field(default_factory = list)
    rekall_plugin_parameters: List[str] = field(default_factory = list)


class VolatilityTest:
    short_name = "true"
    long_name = "True"

    def __init__(self, path: str, output_directory: str) -> None:
        self.path = path
        self.output_directory = output_directory

    def result_titles(self) -> List[str]:
        return [self.long_name]

    def create_prerequisites(self, plugin: VolatilityPlugin, image: VolatilityImage, image_hash: str) -> None:
        pass

    def create_results(self, plugin: VolatilityPlugin, image: VolatilityImage, image_hash: str) -> List[float]:
        self.create_prerequisites(plugin, image, image_hash)

        # Volatility 2 Test
        print(f"[*] Testing {self.short_name} {plugin.name} with image {image.filepath}")
        os.chdir(self.path)
        cmd = self.plugin_cmd(plugin, image)
        start_time = time.perf_counter()
        try:
            completed = subprocess.run(cmd, cwd = self.path, capture_output = True, timeout = 420)
        except subprocess.TimeoutExpired as excp:
            completed = excp
        end_time = time.perf_counter()
        total_time = end_time - start_time
        print(f"    Tested  {self.short_name} {plugin.name} with image {image.filepath}: {total_time}")
        with open(
                os.path.join(self.output_directory, f'{self.short_name}_{plugin.name}_{image_hash}_stdout'),
                "wb") as f:
            f.write(completed.stdout)
        if completed.stderr:
            with open(
                    os.path.join(self.output_directory, f'{self.short_name}_{plugin.name}_{image_hash}_stderr'),
                    "wb") as f:
                f.write(completed.stderr)
        return [total_time]

    def plugin_cmd(self, plugin: VolatilityPlugin, image: VolatilityImage):
        return ["true"]


class Volatility2Test(VolatilityTest):
    short_name = "vol2"
    long_name = "Volatility 2"

    def plugin_cmd(self, plugin: VolatilityPlugin, image: VolatilityImage):
        return ["python2", "-u", "vol.py", "-f", image.filepath, "--profile", image.vol2_profile
                ] + plugin.vol2_plugin_parameters + image.vol2_plugin_parameters.get(plugin.name, [])

    def result_titles(self):
        return [self.long_name, "Imageinfo", f"{self.long_name} + Imageinfo"]

    def create_results(self, plugin: VolatilityPlugin, image: VolatilityImage, image_hash) -> List[float]:
        result = super().create_results(plugin, image, image_hash)
        result += [image.vol2_imageinfo_time, result[0] + image.vol2_imageinfo_time]
        return result

    def create_prerequisites(self, plugin: VolatilityPlugin, image: VolatilityImage, image_hash):
        # Volatility 2 image info
        if not image.vol2_profile:
            print(f"[*] Testing {self.short_name} imageinfo with image {image.filepath}")
            os.chdir(self.path)
            cmd = ["python2", "-u", "vol.py", "-f", image.filepath, "imageinfo"]
            start_time = time.perf_counter()
            vol2_completed = subprocess.run(cmd, cwd = self.path, capture_output = True)
            end_time = time.perf_counter()
            image.vol2_imageinfo_time = end_time - start_time
            print(f"    Tested  volatility2 imageinfo with image {image.filepath}: {end_time - start_time}")
            with open(os.path.join(self.output_directory, f'vol2_imageinfo_{image_hash}_stdout'), "wb") as f:
                f.write(vol2_completed.stdout)
            image.vol2_profile = re.search(b"Suggested Profile\(s\) : ([^,]+)", vol2_completed.stdout)[1]


class RekallTest(VolatilityTest):
    short_name = "rekall"
    long_name = "Rekall"

    def plugin_cmd(self, plugin: VolatilityPlugin, image: VolatilityImage) -> List[str]:
        if not plugin.rekall_plugin_parameters:
            plugin.rekall_plugin_parameters = plugin.vol2_plugin_parameters
        if not image.rekall_plugin_parameters:
            image.rekall_plugin_parameters = image.vol2_plugin_parameters
        return ["rekall", "-f", image.filepath] + plugin.rekall_plugin_parameters + image.rekall_plugin_parameters.get(
            plugin.name, [])

    def create_prerequisites(self, plugin: VolatilityPlugin, image: VolatilityImage, image_hash: str) -> None:
        shutil.rmtree('/home/mike/.rekall_cache/sessions')


class Volatility3Test(VolatilityTest):
    short_name = "vol3"
    long_name = "Volatility 3"

    def plugin_cmd(self, plugin: VolatilityPlugin, image: VolatilityImage) -> List[str]:
        return [
            "python",
            "-u",
            "vol.py",
            "-q",
            "-f",
            image.filepath,
        ] + plugin.vol3_plugin_parameters + image.vol3_plugin_parameters.get(plugin.name, [])


class Volatility3PyPyTest(VolatilityTest):
    short_name = "pypy"
    long_name = "Volatility 3 (PyPy)"

    def plugin_cmd(self, plugin: VolatilityPlugin, image: VolatilityImage) -> List[str]:
        return [
            "pypy3",
            "-u",
            "vol.py",
            "-q",
            "-f",
            image.filepath,
        ] + plugin.vol3_plugin_parameters + image.vol3_plugin_parameters.get(plugin.name, [])


class VolatilityTester:

    def __init__(self,
                 images: List[VolatilityImage],
                 plugins: List[VolatilityPlugin],
                 frameworks: List[str],
                 output_dir: str,
                 vol2_path: str = None,
                 vol3_path: str = None,
                 rekall_path = None):
        self.images = images
        self.plugins = plugins
        if not vol2_path:
            vol2_path = output_dir
        if not vol3_path:
            vol3_path = output_dir
        if not rekall_path:
            rekall_path = output_dir
        available_tests = [
            Volatility3Test(vol3_path, output_dir),
            Volatility3PyPyTest(vol3_path, output_dir),
            Volatility2Test(vol2_path, output_dir),
            RekallTest(rekall_path, output_dir)
        ]
        self.tests = [x for x in available_tests if x.short_name.lower() in frameworks]
        self.csv_writer = None
        print(f"[?] Vol2 path {vol2_path}")
        print(f"[?] Vol3 path {vol3_path}")
        print(f"[?] Rekall path {rekall_path}")
        print("")
        print(f"[?] Frameworks: {[x.long_name for x in self.tests]}")

    def run_tests(self):
        with open("volatility-timings.csv", 'w') as csvfile:
            self.csv_writer = csv.writer(csvfile)
            titles = ["Image Hash", "Image Path", "Plugin Name"]
            for test in self.tests:
                titles += test.result_titles()
            self.csv_writer.writerow(titles)
            for image in self.images:
                for plugin in self.plugins:
                    self.run_test(plugin, image)

    def run_test(self, plugin: VolatilityPlugin, image: VolatilityImage):
        image_hash = hashlib.md5(bytes(image.filepath, "latin-1")).hexdigest()

        results = []
        for test in self.tests:
            results += test.create_results(plugin, image, image_hash)

        self.csv_writer.writerow([image_hash, image.filepath, plugin.name] + results)


if __name__ == '__main__':
    plugins = [
        VolatilityPlugin(name = "pslist",
                         vol2_plugin_parameters = ["pslist"],
                         vol3_plugin_parameters = ["windows.pslist"]),
        VolatilityPlugin(name = "psscan",
                         vol2_plugin_parameters = ["psscan"],
                         vol3_plugin_parameters = ["windows.psscan"],
                         rekall_plugin_parameters = ["psscan", "--scan_kernel"]),
        VolatilityPlugin(name = "driverscan",
                         vol2_plugin_parameters = ["driverscan"],
                         vol3_plugin_parameters = ["windows.driverscan"],
                         rekall_plugin_parameters = ["driverscan", "--scan_kernel"]),
        VolatilityPlugin(name = "handles",
                         vol2_plugin_parameters = ["handles"],
                         vol3_plugin_parameters = ["windows.handles"]),
        VolatilityPlugin(name = "modules",
                         vol2_plugin_parameters = ["modules"],
                         vol3_plugin_parameters = ["windows.modules"]),
        VolatilityPlugin(name = "hivelist",
                         vol2_plugin_parameters = ["hivelist"],
                         vol3_plugin_parameters = ["registry.hivelist"],
                         rekall_plugin_parameters = ["hives"]),
        VolatilityPlugin(name = "vadinfo",
                         vol2_plugin_parameters = ["vadinfo"],
                         vol3_plugin_parameters = ["windows.vadinfo"],
                         rekall_plugin_parameters = ["vad"]),
        VolatilityPlugin(name = "modscan",
                         vol2_plugin_parameters = ["modscan"],
                         vol3_plugin_parameters = ["windows.modscan"],
                         rekall_plugin_parameters = ["modscan", "--scan_kernel"]),
        VolatilityPlugin(name = "svcscan",
                         vol2_plugin_parameters = ["svcscan"],
                         vol3_plugin_parameters = ["windows.svcscan"],
                         rekall_plugin_parameters = ["svcscan"]),
        VolatilityPlugin(name = "ssdt", vol2_plugin_parameters = ["ssdt"], vol3_plugin_parameters = ["windows.ssdt"]),
        VolatilityPlugin(name = "printkey",
                         vol2_plugin_parameters = ["printkey", "-K", "Classes"],
                         vol3_plugin_parameters = ["registry.printkey", "--key", "Classes"],
                         rekall_plugin_parameters = ["printkey", "--key", "Classes"])
    ]

    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type = str, default = os.getcwd(), help = "Directory to store all results")
    parser.add_argument("--vol3path",
                        type = str,
                        default = os.path.join(os.getcwd(), 'volatility3'),
                        help = "Path ot the volatility 3 directory")
    parser.add_argument("--vol2path",
                        type = str,
                        default = os.path.join(os.getcwd(), 'volatility'),
                        help = "Path to the volatility 2 directory")
    parser.add_argument("--rekallpath",
                        type = str,
                        default = os.path.join(os.getcwd(), 'rekall'),
                        help = "Path to the rekall directory")
    parser.add_argument("--frameworks",
                        nargs = "+",
                        type = str,
                        choices = [x.short_name.lower() for x in VolatilityTest.__subclasses__()],
                        default = [x.short_name.lower() for x in VolatilityTest.__subclasses__()],
                        help = "A comma separated list of frameworks to test")
    parser.add_argument('images', metavar = 'IMAGE', type = str, nargs = '+', help = 'The list of images to compare')
    args = parser.parse_args()

    vt = VolatilityTester([VolatilityImage(filepath = x) for x in args.images], plugins,
                          [x.lower() for x in args.frameworks], args.output_dir, args.vol2path, args.vol3path,
                          args.rekallpath)
    vt.run_tests()
