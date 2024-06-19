import logging
from typing import Callable, Tuple, List, Optional

from volatility3.framework import interfaces, constants, exceptions

vollog = logging.getLogger(__name__)


class OsDistinguisher:
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

    def __init__(
        self,
        version_check: Callable[[Tuple[int, ...]], bool],
        fallback_checks: List[Tuple[str, Optional[str], bool]],
    ) -> None:
        self._version_check = version_check
        self._fallback_checks = fallback_checks

    # try the primary method based on the pe version in the ISF
    def __call__(
        self, context: interfaces.context.ContextInterface, symbol_table: str
    ) -> bool:
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
            return self._version_check((major, minor, revision, build))
        except (AttributeError, ValueError, TypeError):
            vollog.log(
                constants.LOGLEVEL_VVV, "Windows PE version data is not available"
            )

        # fall back to the backup method, if necessary
        for name, member, response in self._fallback_checks:
            if member is None:
                if (
                    context.symbol_space.has_symbol(
                        symbol_table + constants.BANG + name
                    )
                    or context.symbol_space.has_type(
                        symbol_table + constants.BANG + name
                    )
                ) != response:
                    return False
            else:
                try:
                    symbol_type = context.symbol_space.get_type(
                        symbol_table + constants.BANG + name
                    )
                    if symbol_type.has_member(member) != response:
                        return False
                except exceptions.SymbolError:
                    if not response:
                        return False

        return True


is_windows_8_1_or_later = OsDistinguisher(
    version_check=lambda x: x >= (6, 3),
    fallback_checks=[("_KPRCB", "PendingTickFlags", True)],
)

is_vista_or_later = OsDistinguisher(
    version_check=lambda x: x >= (6, 0),
    fallback_checks=[("KdCopyDataBlock", None, True)],
)

is_win10 = OsDistinguisher(
    version_check=lambda x: (10, 0) <= x,
    fallback_checks=[
        ("ObHeaderCookie", None, True),
        ("_HANDLE_TABLE", "HandleCount", False),
    ],
)

is_windows_xp = OsDistinguisher(
    version_check=lambda x: (5, 1) <= x < (5, 2),
    fallback_checks=[
        ("KdCopyDataBlock", None, False),
        ("_HANDLE_TABLE", "HandleCount", True),
    ],
)

is_xp_or_2003 = OsDistinguisher(
    version_check=lambda x: (5, 1) <= x < (6, 0),
    fallback_checks=[
        ("KdCopyDataBlock", None, False),
        ("_HANDLE_TABLE", "HandleCount", True),
    ],
)

is_win10_up_to_15063 = OsDistinguisher(
    version_check=lambda x: (10, 0) <= x < (10, 0, 15063),
    fallback_checks=[
        ("ObHeaderCookie", None, True),
        ("_HANDLE_TABLE", "HandleCount", False),
        ("_EPROCESS", "KeepAliveCounter", True),
    ],
)

is_win10_15063 = OsDistinguisher(
    version_check=lambda x: x == (10, 0, 15063),
    fallback_checks=[
        ("ObHeaderCookie", None, True),
        ("_HANDLE_TABLE", "HandleCount", False),
        ("_EPROCESS", "KeepAliveCounter", False),
        ("_EPROCESS", "ControlFlowGuardEnabled", True),
    ],
)

is_win10_15063_or_later = OsDistinguisher(
    version_check=lambda x: x >= (10, 0, 15063),
    fallback_checks=[
        ("ObHeaderCookie", None, True),
        ("_HANDLE_TABLE", "HandleCount", False),
        ("_EPROCESS", "KeepAliveCounter", False),
    ],
)

is_win10_16299_or_later = OsDistinguisher(
    version_check=lambda x: x >= (10, 0, 16299),
    fallback_checks=[
        ("ObHeaderCookie", None, True),
        ("_HANDLE_TABLE", "HandleCount", False),
        ("_EPROCESS", "KeepAliveCounter", False),
        ("_EPROCESS", "ControlFlowGuardEnabled", False),
    ],
)

is_win10_17763_or_later = OsDistinguisher(
    version_check=lambda x: x >= (10, 0, 17763),
    fallback_checks=[
        ("_EPROCESS", "TrustletIdentity", False),
        ("ParentSecurityDomain", None, True),
    ],
)

is_win10_18362_or_later = OsDistinguisher(
    version_check=lambda x: x >= (10, 0, 18362),
    fallback_checks=[
        ("ObHeaderCookie", None, True),
        ("_CM_CACHED_VALUE_INDEX", None, False),
        ("_WNF_PROCESS_CONTEXT", None, True),
    ],
)

is_win10_18363_or_later = OsDistinguisher(
    version_check=lambda x: x >= (10, 0, 18363),
    fallback_checks=[("_KQOS_GROUPING_SETS", None, True)],
)

is_win10_19041_or_later = OsDistinguisher(
    version_check=lambda x: x >= (10, 0, 19041),
    fallback_checks=[
        ("_EPROCESS", "TimerResolutionIgnore", True),
        ("_EPROCESS", "VmProcessorHostTransition", True),
        ("_KQOS_GROUPING_SETS", None, True),
    ],
)

is_win10_25398_or_later = OsDistinguisher(
    version_check=lambda x: x >= (10, 0, 25398),
    fallback_checks=[
        ("_EPROCESS", "MmSlabIdentity", True),
        ("_EPROCESS", "EnableProcessImpersonationLogging", True),
    ],
)

is_windows_10 = OsDistinguisher(
    version_check=lambda x: x >= (10, 0),
    fallback_checks=[("ObHeaderCookie", None, True)],
)

is_windows_8_or_later = OsDistinguisher(
    version_check=lambda x: x >= (6, 2),
    fallback_checks=[("_HANDLE_TABLE", "HandleCount", False)],
)
# Technically, this is win7 or less
is_windows_7 = OsDistinguisher(
    version_check=lambda x: x == (6, 1),
    fallback_checks=[
        ("_OBJECT_HEADER", "TypeIndex", True),
        ("_HANDLE_TABLE", "HandleCount", True),
    ],
)
