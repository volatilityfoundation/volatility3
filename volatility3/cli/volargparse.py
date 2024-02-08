# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import argparse
import gettext
import re
from typing import List, Optional, Sequence, Any, Union


# This effectively overrides/monkeypatches the core argparse module to provide more helpful output around choices
# We shouldn't really steal a private member from argparse, but otherwise we're just duplicating code

# HelpfulSubparserAction gives more information about the possible choices from a subparsed choice
# HelpfulArgParser gives the list of choices when no arguments are provided to a choice option whilst still using a


class HelpfulSubparserAction(argparse._SubParsersAction):
    """Class to either select a unique plugin based on a substring, or identify
    the alternatives."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # We don't want the action self-check to kick in, so we remove the choices list, the check happens in __call__
        self.choices = None

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None],
        option_string: Optional[str] = None,
    ) -> None:
        parser_name = ""
        arg_strings = []  # type: List[str]
        if values is not None:
            for value in values:
                if not parser_name:
                    parser_name = value
                else:
                    arg_strings += [value]

        # set the parser name if requested
        if self.dest != argparse.SUPPRESS:
            setattr(namespace, self.dest, parser_name)

        matched_parsers = [
            name for name in self._name_parser_map if parser_name in name
        ]

        if len(matched_parsers) < 1:
            msg = f"invalid choice {parser_name} (choose from {', '.join(self._name_parser_map)})"
            raise argparse.ArgumentError(self, msg)
        if len(matched_parsers) > 1:
            msg = f"plugin {parser_name} matches multiple plugins ({', '.join(matched_parsers)})"
            raise argparse.ArgumentError(self, msg)
        parser = self._name_parser_map[matched_parsers[0]]
        setattr(namespace, "plugin", matched_parsers[0])

        # parse all the remaining options into the namespace
        # store any unrecognized options on the object, so that the top
        # level parser can decide what to do with them

        # In case this subparser defines new defaults, we parse them
        # in a new namespace object and then update the original
        # namespace for the relevant parts.
        subnamespace, arg_strings = parser.parse_known_args(arg_strings, None)
        for key, value in vars(subnamespace).items():
            setattr(namespace, key, value)

        if arg_strings:
            vars(namespace).setdefault(argparse._UNRECOGNIZED_ARGS_ATTR, [])
            getattr(namespace, argparse._UNRECOGNIZED_ARGS_ATTR).extend(arg_strings)


class HelpfulArgParser(argparse.ArgumentParser):
    def _match_argument(self, action, arg_strings_pattern) -> int:
        # match the pattern for this action to the arg strings
        nargs_pattern = self._get_nargs_pattern(action)
        match = re.match(nargs_pattern, arg_strings_pattern)

        # raise an exception if we weren't able to find a match
        if match is None:
            nargs_errors = {
                None: gettext.gettext("expected one argument"),
                argparse.OPTIONAL: gettext.gettext("expected at most one argument"),
                argparse.ONE_OR_MORE: gettext.gettext("expected at least one argument"),
            }
            msg = nargs_errors.get(action.nargs)
            if msg is None:
                msg = (
                    gettext.ngettext(
                        "expected %s argument", "expected %s arguments", action.nargs
                    )
                    % action.nargs
                )
            if action.choices:
                msg = f"{msg} (from: {', '.join(action.choices)})"
            raise argparse.ArgumentError(action, msg)

        # return the number of arguments matched
        return len(match.group(1))
