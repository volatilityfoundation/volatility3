import argparse
import lzma
import os
import subprocess
import tempfile
from typing import List, Dict

import requests
import rpmfile

DWARF2JSON = './dwarf2json'


class Downloader:

    def __init__(self, url_lists: List[List[str]]) -> None:
        self.url_lists = url_lists

    def download_lists(self):
        for url_list in self.url_lists:
            print("Downloading files...")
            files_for_processing = self.download_list(url_list)
            self.process_files(files_for_processing)
            for fname in files_for_processing.values():
                os.unlink(fname)

    def download_list(self, urls: List[str]) -> Dict[str, str]:
        processed_files = {}
        for url in urls:
            print(" - Downloading {}".format(url))
            data = requests.get(url)
            with tempfile.NamedTemporaryFile() as rpmdata:
                rpmdata.write(data.content)
                rpmdata.seek(0)
                rpm = rpmfile.RPMFile(fileobj = rpmdata)
                for member in rpm.getmembers():
                    if 'vmlinux' in member.name or 'System.map' in member.name:
                        print(" - Extracting {}".format(member.name))
                        extracted = rpm.extractfile(member)
                        break
                with tempfile.NamedTemporaryFile(
                        delete = False, prefix = 'vmlinux' if 'vmlinux' in member.name else 'System.map') as output:
                    print(" - Writing to {}".format(output.name))
                    output.write(extracted.read())
                    processed_files[url] = output.name
        return processed_files

    def process_files(self, named_files: Dict[str, str]):
        """Runs the dwarf2json binary across the files"""
        print("Processing Files...")
        args = [DWARF2JSON, 'linux']
        output_filename = 'unknown-kernel.json'
        for named_file in named_files:
            prefix = '--system-map'
            if not 'System' in named_files[named_file]:
                prefix = '--elf'
                output_filename = './' + '-'.join((named_file.split('/')[-1]).split('-')[2:])[:-4] + '.json.xz'
            args += [prefix, named_files[named_file]]
        print(" - Running {}".format(args))
        proc = subprocess.run(args, capture_output = True)

        print(" - Writing to {}".format(output_filename))
        with lzma.open(output_filename, 'w') as f:
            f.write(proc.stdout)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = "Takes a list of URLs for Centos and downloads them")
    parser.add_argument("-f",
                        "--file",
                        dest = 'filename',
                        metavar = "FILENAME",
                        help = "Filename to be read",
                        required = True)
    parser.add_argument("-d",
                        "--dwarf2json",
                        dest = 'dwarfpath',
                        metavar = "PATH",
                        default = DWARF2JSON,
                        help = "Path to the dwarf2json binary",
                        required = True)
    args = parser.parse_args()

    DWARF2JSON = args.dwarfpath

    with open(args.filename) as f:
        lines = f.readlines()

    urls = []
    for i in range(len(lines) // 2):
        urls += [[lines[2 * i].strip(), lines[(2 * i) + 1].strip()]]

    d = Downloader(urls)
    d.download_lists()
