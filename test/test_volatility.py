# volatility3 tests
#

#
# IMPORTS
#

import os
import subprocess
import sys
import tempfile
import contextlib
import functools
import json
import logging
from typing import List, Tuple

from test import WINDOWS_TESTS_DATA_DIR

test_logger = logging.getLogger(__name__)


#
# HELPER FUNCTIONS
#


@functools.lru_cache
def runvol(args, volatility, python):
    volpy = volatility
    python_cmd = python

    cmd = (python_cmd, volpy) + args
    print(" ".join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    print("stdout:")
    sys.stdout.write(str(stdout))
    print("")
    print("stderr:")
    sys.stdout.write(str(stderr))
    print("")

    return p.returncode, stdout, stderr


@functools.lru_cache
def runvol_plugin(
    plugin, img, volatility, python, pluginargs: Tuple = (), globalargs: Tuple = ()
):
    args = (
        globalargs
        + (
            "--single-location",
            img,
            "-q",
            plugin,
        )
        + pluginargs
    )

    return runvol(args, volatility, python)


def runvolshell(
    img, volshell, python, volshellargs: Tuple = (), globalargs: Tuple = ()
):
    args = (
        globalargs
        + (
            "--single-location",
            img,
            "-q",
        )
        + volshellargs
    )

    return runvol(args, volshell, python)


def load_test_data(plugin: str, test_key: str):
    if plugin.startswith("windows."):
        data_path = WINDOWS_TESTS_DATA_DIR / f"{plugin}.json"
    # TODO: add Linux and macOS when any of these requires this API
    else:
        raise Exception(f"Cannot determine OS of plugin: {plugin}")

    if not data_path.exists():
        raise FileNotFoundError(
            f"Test data not found for plugin {plugin} at {data_path}"
        )

    with open(data_path) as f:
        # This will raise an explicit exception by itself on failures
        return json.load(f)[test_key]


def dict_lower_strvalues(dict_to_convert: dict):
    """Lower each value of type string of a dictionary

    Args:
        dict_to_convert: The dictionary in which to lower the string values
    Returns:
        A copy of the dictionary with lowered string values
    """

    converted = {}
    for key, value in dict_to_convert.items():
        if isinstance(value, str):
            converted[key] = value.lower()
        else:
            converted[key] = value
    return converted


def match_output_row(
    expected_row: dict,
    plugin_json_out: List[dict],
    exact_match: bool = False,
    case_sensitive: bool = True,
    children_recursive: bool = False,
):
    """Search each row in a plugin's JSON output for a matching row.
        This method supports recursive comparisons using the "__children" key, making it useful for testing hierarchical plugins like windows.pstree.
        It also maintains case sensitivity and exact matching behavior when traversing nested structures.

        Args:
            expected_row: The expected row to be found in the output
            plugin_json_out: The plugin's output in JSON format (typically obtained through -r json and json.loads)
            exact_match: Require exactly the expected row, no more no less, or anticipate columns' addition by checking only
    the expected row keys and values
            case_sensitive: Operate case sensitive match for str values of both dictionaries or not
            children_recursive: Perform a recursive match by inspecting "__children" keys of each expected_row

        Returns:
            A boolean indicating whether a match was found or not
    """

    # Lower each string value of both dicts
    if not case_sensitive:
        expected_row = dict_lower_strvalues(expected_row)
        plugin_json_out_tmp = []
        for row in plugin_json_out:
            plugin_json_out_tmp.append(dict_lower_strvalues(row))
        plugin_json_out = plugin_json_out_tmp

    if not exact_match:
        for row in plugin_json_out:
            if all(
                expected_item in row.items()
                for expected_item in expected_row.items()
                if not expected_item[0] == "__children"
            ):
                if (
                    children_recursive
                    and "__children" in expected_row
                    and "__children" in row
                ):
                    for children_expected_row in expected_row["__children"]:
                        if not match_output_row(
                            children_expected_row,
                            row["__children"],
                            case_sensitive=case_sensitive,
                            children_recursive=True,
                        ):
                            break
                    else:
                        # We matched all the children keys
                        return True
                else:
                    # No recursion required and we already matched the row
                    return True
    else:
        # No "__children" recursion here as we want to match the whole tree at once
        for row in plugin_json_out:
            if expected_row == row:
                return True

    return False


def count_entries_flat(plugin_json_out: List[dict]):
    """Count the number of entries as if -r json wasn't specified. Allows to get a non-hierarchical count, without running a plugin twice
    (once with "-r json" and once without) while still preserving JSON features.

    Args:
        plugin_json_out: The plugin's output in JSON format (typically obtained through -r json and json.loads)
    """
    # Remove whitespaces between entries
    # If a value contains {", it will be represented by {\" so no confusion
    return json.dumps(plugin_json_out, separators=(",", ":")).count('{"')


#
# TESTS
#


def basic_volshell_test(
    image, volatility, python, volshellargs: Tuple = (), globalargs: Tuple = ()
):
    # Basic VolShell test to verify requirements and ensure VolShell runs without crashing

    volshell_commands = [
        "print(ps())",
        "exit()",
    ]

    # FIXME: When the minimum Python version includes 3.12, replace the following with:
    # with tempfile.NamedTemporaryFile(delete_on_close=False) as fd: ...
    fd, filename = tempfile.mkstemp(suffix=".txt")
    try:
        volshell_script = "\n".join(volshell_commands)
        with os.fdopen(fd, "w") as f:
            f.write(volshell_script)

        rc, out, _err = runvolshell(
            img=image,
            volshell=volatility,
            python=python,
            volshellargs=("--script", filename) + volshellargs,
            globalargs=globalargs,
        )
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.remove(filename)

    assert rc == 0
    assert out.count(b"\n") >= 4

    return out


# MAC
# TODO: Migrate and integrate in testing (once analysis is fixed ?)


def test_mac_volshell(image, volatility, python):
    basic_volshell_test(image, volatility, python, globalargs=["-m"])


def test_mac_pslist(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.pslist.PsList", image, volatility, python)
    out = out.lower()

    assert (out.find(b"kernel_task") != -1) or (out.find(b"launchd") != -1)
    assert out.count(b"\n") > 10
    assert rc == 0


def test_mac_check_syscall(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "mac.check_syscall.Check_syscall", image, volatility, python
    )
    out = out.lower()

    assert out.find(b"chmod") != -1
    assert out.find(b"chown") != -1
    assert out.find(b"nosys") != -1
    assert out.count(b"\n") > 100
    assert rc == 0


def test_mac_check_sysctl(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "mac.check_sysctl.Check_sysctl", image, volatility, python
    )
    out = out.lower()

    assert out.find(b"__kernel__") != -1
    assert out.count(b"\n") > 250
    assert rc == 0


def test_mac_check_trap_table(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "mac.check_trap_table.Check_trap_table", image, volatility, python
    )
    out = out.lower()

    assert out.count(b"kern_invalid") >= 10
    assert out.count(b"\n") > 50
    assert rc == 0


def test_mac_ifconfig(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.ifconfig.Ifconfig", image, volatility, python)
    out = out.lower()

    assert out.find(b"127.0.0.1") != -1
    assert out.find(b"false") != -1
    assert out.count(b"\n") > 9
    assert rc == 0


def test_mac_lsmod(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.lsmod.Lsmod", image, volatility, python)
    out = out.lower()

    assert out.find(b"com.apple") != -1
    assert out.count(b"\n") > 10
    assert rc == 0


def test_mac_lsof(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.lsof.Lsof", image, volatility, python)
    out = out.lower()

    assert out.count(b"\n") > 50
    assert rc == 0


def test_mac_malfind(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.malfind.Malfind", image, volatility, python)
    out = out.lower()

    assert out.count(b"\n") > 20
    assert rc == 0


def test_mac_mount(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.mount.Mount", image, volatility, python)
    out = out.lower()

    assert out.find(b"/dev") != -1
    assert out.count(b"\n") > 7
    assert rc == 0


def test_mac_netstat(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.netstat.Netstat", image, volatility, python)

    assert out.find(b"TCP") != -1
    assert out.find(b"UDP") != -1
    assert out.find(b"UNIX") != -1
    assert out.count(b"\n") > 10
    assert rc == 0


def test_mac_proc_maps(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.proc_maps.Maps", image, volatility, python)
    out = out.lower()

    assert out.find(b"[heap]") != -1
    assert out.count(b"\n") > 100
    assert rc == 0


def test_mac_psaux(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.psaux.Psaux", image, volatility, python)
    out = out.lower()

    assert out.find(b"executable_path") != -1
    assert out.count(b"\n") > 50
    assert rc == 0


def test_mac_socket_filters(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "mac.socket_filters.Socket_filters", image, volatility, python
    )
    out = out.lower()

    assert out.count(b"\n") > 9
    assert rc == 0


def test_mac_timers(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.timers.Timers", image, volatility, python)
    out = out.lower()

    assert out.count(b"\n") > 6
    assert rc == 0


def test_mac_trustedbsd(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "mac.trustedbsd.Trustedbsd", image, volatility, python
    )
    out = out.lower()

    assert out.count(b"\n") > 10
    assert rc == 0
