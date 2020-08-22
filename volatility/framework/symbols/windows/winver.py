import logging
from typing import Callable, Tuple, List, Optional

from volatility.framework import interfaces, constants, exceptions

vollog = logging.getLogger(__name__)


def os_distinguisher(
        version_check: Callable[[Tuple[int, ...]], bool],
        fallback_checks: List[Tuple[str, Optional[str],
                                    bool]]) -> Callable[[interfaces.context.ContextInterface, str], bool]:
    """Distinguishes a symbol table as being above a particular version or
    point.

    This will primarily check the version metadata first and foremost.
    If that metadata isn't available then each item in the fallback_checks is tested.
    If invert is specified then the result will be true if the version is less than that specified, or in the case of
    fallback, if any of the fallback checks is successful.

    A fallback check is made up of:
     * a symbol or type name
     * a member name (implying that the value before was a type name)
     * whether that symbol, type or member must be present or absent for the symbol table to be more above the required point

    Note:
        Specifying that a member must not be present includes the whole type not being present too (ie, either will pass the test)

    Args:
        version_check: Function that takes a 4-tuple version and returns whether whether the provided version is above a particular point
        fallback_checks: A list of symbol/types/members of types, and whether they must be present to be above the required point

    Returns:
        A function that takes a context and a symbol table name and determines whether that symbol table passes the distinguishing checks
    """

    # try the primary method based on the pe version in the ISF
    def method(context: interfaces.context.ContextInterface, symbol_table: str) -> bool:
        """

        Args:
            context: The context that contains the symbol table named `symbol_table`
            symbol_table: Name of the symbol table within the context to distinguish the version of

        Returns:
            True if the symbol table is of the required version
        """

        try:
            pe_version = context.symbol_space[symbol_table].metadata.pe_version
            major, minor, revision, build = pe_version
            return version_check((major, minor, revision, build))
        except (AttributeError, ValueError, TypeError):
            vollog.log(constants.LOGLEVEL_VVV, "Windows PE version data is not available")

        # fall back to the backup method, if necessary
        for name, member, response in fallback_checks:
            if member is None:
                if (context.symbol_space.has_symbol(symbol_table + constants.BANG + name)
                    or context.symbol_space.has_type(symbol_table + constants.BANG + name)) != response:
                    return False
            else:
                try:
                    symbol_type = context.symbol_space.get_type(symbol_table + constants.BANG + name)
                    if symbol_type.has_member(member) != response:
                        return False
                except exceptions.SymbolError:
                    if not response:
                        return False

        return True

    return method
