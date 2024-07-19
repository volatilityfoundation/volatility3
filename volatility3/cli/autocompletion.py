# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import os
import textwrap
from typing import Dict, List, Tuple

BASE_COMPLETION = """
# Volatility3 {shell} completion start{script}# Volatility3 {shell} completion end
"""

COMPLETION_SCRIPTS = {
    "bash": """
        _vol3_completion()
        {{
            COMPREPLY=( $( COMP_WORDS="${{COMP_WORDS[*]}}" \\
                           COMP_CWORD=$COMP_CWORD \\
                           {vol3_env_var}=1 $1 2>/dev/null ) )
        }}
        complete -o default -o nosort -F _vol3_completion {prog}
    """,
    "fish": """
        function __fish_complete_vol3
            set -lx COMP_WORDS (commandline -o) ""
            set -lx COMP_CWORD ( \\
                math (contains -i -- (commandline -t) $COMP_WORDS)-1 \\
            )
            set -lx {vol3_env_var} 1
            string split \\  -- (eval $COMP_WORDS[1])
        end
        complete -fa "(__fish_complete_vol3)" -c {prog}
    """,
}


class AutoCompletion(object):
    AUTOCOMPLETION_ACTIVATION_ENV = "VOLATILITY3_AUTOCOMPLETION"

    AVAILABLE_SHELLS = sorted(COMPLETION_SCRIPTS)
    ACTION_GROUP_OPTIONS_INDEX = 1
    ACTION_GROUP_PLUGINS_INDEX = 2

    def __init__(self, parser, skip_single_dash=True, skip_help=True):
        if not self.is_enabled():
            # Autocompletions wasn't requested
            return

        self._parser = parser
        self._skip_single_dash = skip_single_dash
        self._skip_help = skip_help
        self._comp_words = [w for w in os.environ["COMP_WORDS"].split() if w]
        self._comp_cword = int(os.environ["COMP_CWORD"])
        self._main_options, self._plugins_options = self._extract_options()

    @classmethod
    def is_enabled(cls) -> bool:
        """Check if autocompletion is enabled in the shell"""
        return (
            cls.AUTOCOMPLETION_ACTIVATION_ENV in os.environ
            and "COMP_WORDS" in os.environ
            and "COMP_CWORD" in os.environ
        )

    @staticmethod
    def get_script_template(shell_name) -> str:
        """Return the autocompletion script template for a given shell

        Args:
            shell_name (str): The name of the script. It needs to match the COMPLETION_SCRIPTS keys

        Raises:
            RuntimeError: If the requested shell is not supported.

        Returns:
            str: The activation script template for the requested shell.
        """
        script_template = COMPLETION_SCRIPTS.get(shell_name)
        if not script_template:
            raise RuntimeError(f"Shell '{shell_name}' not supported for autocompletion")

        activation_script = textwrap.dedent(script_template)
        activation_script = BASE_COMPLETION.format(
            script=activation_script, shell=shell_name
        )
        return activation_script

    def _extract_options(self) -> Tuple[Dict, Dict]:
        """Extract the options from argparse.

        Returns:
            tuple: containing the main options and the plugins options
        """
        action_groups = self._parser._action_groups

        # Option groups - There are n groups, one per each main option
        main_actions = action_groups[self.ACTION_GROUP_OPTIONS_INDEX]._group_actions
        main_options = {}
        for main_action in main_actions:
            for option in main_action.option_strings:
                if self._skip_single_dash and not option.startswith("--"):
                    continue
                if self._skip_help and option in ("-h", "--help"):
                    continue

                main_options.setdefault(option, None)
                if main_action.choices:
                    main_options[option] = list(main_action.choices)

        # Plugin group - There is just one group with n parsers, one per each plugin
        plugin_groups = action_groups[self.ACTION_GROUP_PLUGINS_INDEX]._group_actions
        plugins_parsers = plugin_groups[0]._name_parser_map
        # Plugin options are in the same group
        plugins_options = {}
        for plugin_name, plugin_parser in plugins_parsers.items():
            plugins_options.setdefault(plugin_name, {})
            plugin_actions = plugin_parser._option_string_actions
            for option_name, plugin_action in plugin_actions.items():
                if (
                    self._skip_single_dash
                    and option_name.startswith("-")
                    and not option_name.startswith("--")
                ):
                    continue
                if self._skip_help and option_name in ("-h", "--help"):
                    continue

                plugins_options[plugin_name].setdefault(option_name, [])
                if plugin_action.choices:
                    plugins_options[plugin_name][option_name].extend(
                        plugin_action.choices
                    )

        return main_options, plugins_options

    def _get_current_plugin(self) -> str:
        # The first word matching a plugin name is the current plugin name
        for comp_word in self._comp_words[1:]:
            if comp_word in self._plugins_options:
                return comp_word

    def _incomplete_argument(self) -> bool:
        return self._comp_cword < len(self._comp_words)

    def _autocomplete_dash_option(self):
        return self._incomplete_argument() and self._comp_words[-1].startswith("-")

    def _in_dash_argument(self) -> bool:
        len_comp_words = len(self._comp_words)
        return not self._autocomplete_dash_option() and (
            (len_comp_words >= 2 and self._comp_words[-1].startswith("-"))
            or (len_comp_words >= 3 and self._comp_words[-2].startswith("-"))
        )

    def _cmdline_context_words(self) -> List[str]:
        """Identify where the command line is standing, providing the correct
        options for such context.

        Returns:
            List[str]: The appropriate list of options for the current command
                       line
        """
        current_plugin = self._get_current_plugin()
        all_options = list(self._main_options) + list(self._plugins_options)
        if current_plugin:
            options = self._plugins_options[current_plugin]
        else:
            options = self._main_options

        if len(self._comp_words) == 1:
            # Case: vol <tab>
            sub_options = all_options
        elif self._autocomplete_dash_option():
            # Case: vol -<tab> or vol plugin -<tab>
            sub_options = options
        elif self._in_dash_argument():
            if self._incomplete_argument():
                # Case: vol --parallelism th<tab>
                arg = self._comp_words[-2]
            else:
                # Case: vol --parallelism <tab>
                arg = self._comp_words[-1]
            sub_options = options[arg]
        elif self._incomplete_argument():
            # Case: vol linu<tab>
            sub_options = all_options
        else:
            # Case: vol linux.pslist.PsList <tab>
            sub_options = options

        return list(sub_options)

    def process_commandline(self) -> bool:
        """Process the current command line and print the autocompletion tokens"""
        if not self.is_enabled():
            return False

        words = self._cmdline_context_words()
        for word in words:
            if self._incomplete_argument():
                if word.startswith(self._comp_words[-1]):
                    print(word)
            else:
                print(word)

        return True
