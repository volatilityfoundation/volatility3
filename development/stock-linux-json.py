import argparse
import lzma
import os
import subprocess
import tempfile
from typing import List, Dict, Optional

import requests
import rpmfile
from debian import debfile

DWARF2JSON = "./dwarf2json"


class Downloader:

    def __init__(self, url_lists: List[List[str]]) -> None:
        self.url_lists = url_lists

    def download_lists(self, keep=False):
        for url_list in self.url_lists:
            print("Downloading files...")
            files_for_processing = self.download_list(url_list)
            self.process_files(files_for_processing)
            if not keep:
                for fname in files_for_processing.values():
                    if fname:
                        os.unlink(fname)

    def download_list(self, urls: List[str]) -> Dict[str, str]:
        processed_files = {}
        for url in urls:
            print(f" - Downloading {url}")
            data = requests.get(url)
            with tempfile.NamedTemporaryFile() as archivedata:
                archivedata.write(data.content)
                archivedata.seek(0)
                if url.endswith(".rpm"):
                    processed_files[url] = self.process_rpm(archivedata)
                elif url.endswith(".deb"):
                    processed_files[url] = self.process_deb(archivedata)

        return processed_files

    def process_rpm(self, archivedata) -> Optional[str]:
        rpm = rpmfile.RPMFile(fileobj=archivedata)
        member = None
        extracted = None
        for member in rpm.getmembers():
            if "vmlinux" in member.name or "System.map" in member.name:
                print(f" - Extracting {member.name}")
                extracted = rpm.extractfile(member)
                break
        if not member or not extracted:
            return None
        with tempfile.NamedTemporaryFile(
            delete=False, prefix="vmlinux" if "vmlinux" in member.name else "System.map"
        ) as output:
            print(f" - Writing to {output.name}")
            output.write(extracted.read())
        return output.name

    def process_deb(self, archivedata) -> Optional[str]:
        deb = debfile.DebFile(fileobj=archivedata)
        member = None
        extracted = None
        for member in deb.data.tgz().getmembers():
            if member.name.endswith("vmlinux") or "System.map" in member.name:
                print(f" - Extracting {member.name}")
                extracted = deb.data.get_file(member.name)
                break
        if not member or not extracted:
            return None
        with tempfile.NamedTemporaryFile(
            delete=False, prefix="vmlinux" if "vmlinux" in member.name else "System.map"
        ) as output:
            print(f" - Writing to {output.name}")
            output.write(extracted.read())
        return output.name

    def process_files(self, named_files: Dict[str, str]):
        """Runs the dwarf2json binary across the files"""
        print("Processing Files...")
        for i in named_files:
            if named_files[i] is None:
                print(f"FAILURE: None encountered for {i}")
                return
        args = [DWARF2JSON, "linux"]
        output_filename = "unknown-kernel.json"
        for named_file in named_files:
            prefix = "--system-map"
            if "System" not in named_files[named_file]:
                prefix = "--elf"
                output_filename = (
                    "./"
                    + "-".join((named_file.split("/")[-1]).split("-")[2:])[:-4]
                    + ".json.xz"
                )
            args += [prefix, named_files[named_file]]
        print(f" - Running {args}")
        proc = subprocess.run(args, capture_output=True)

        print(f" - Writing to {output_filename}")
        with lzma.open(output_filename, "w") as f:
            f.write(proc.stdout)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Takes a list of URLs for Centos and downloads them"
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="filename",
        metavar="FILENAME",
        help="Filename to be read",
        required=True,
    )
    parser.add_argument(
        "-d",
        "--dwarf2json",
        dest="dwarfpath",
        metavar="PATH",
        default=DWARF2JSON,
        help="Path to the dwarf2json binary",
        required=True,
    )
    parser.add_argument(
        "-k",
        "--keep",
        dest="keep",
        action="store_true",
        help="Keep extracted temporary files after completion",
        default=False,
    )
    args = parser.parse_args()

    DWARF2JSON = args.dwarfpath

    with open(args.filename) as f:
        lines = f.readlines()

    urls = []
    for i in range(len(lines) // 2):
        urls += [[lines[2 * i].strip(), lines[(2 * i) + 1].strip()]]

    d = Downloader(urls)
    d.download_lists(keep=args.keep)
