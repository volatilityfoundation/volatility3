"""
This script performs syntax analysis on the volatility3 source tree through a combination of AST analysis and import-time introspection of classes.

The current checks it implements are:
    1. Ensure that classes derived from `ConfigurableInterface` properly
    declare all `VersionableInterface` classes that they make use of in their
    `get_requirements()` classmethod.

    :WARNING: a notable exception to this are classes defined within factory
    functions. Because these classes are not created until the factory function
    is called, they therefore do no exist at import time and cannot be checked
    by this script. It is important to keep in mind during code review that
    this is a best-effort check and does not make guarantees about the
    completeness of declared requirements.
"""

import abc
import argparse
import ast
import importlib
import inspect
import logging
import pkgutil
import sys
import traceback
import types
from typing import Any, Iterator, List, Optional, Tuple, Type, Union

from volatility3.framework import configuration, interfaces
from volatility3.framework.deprecation import PluginRenameClass

logging.basicConfig(format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


class NodeVisitor:
    def visit(self, node):
        """Visit a node."""
        method = "visit_" + node.__class__.__name__
        visitor = getattr(self, method, self.generic_visit)
        self.enter(node)
        result = visitor(node)
        self.leave(node)
        return result

    def enter(self, node):
        """Called when entering a node."""
        method = "enter_" + node.__class__.__name__
        visitor = getattr(self, method, self.generic_enter)
        return visitor(node)

    def leave(self, node):
        """Called when leaving a node."""
        method = "leave_" + node.__class__.__name__
        visitor = getattr(self, method, self.generic_leave)
        return visitor(node)

    def generic_visit(self, node):
        """Called if no explicit visitor function exists for a node."""
        for _, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

    def generic_enter(self, node):
        """Default enter behavior."""

    def generic_leave(self, node):
        """Default leave behavior."""


class CodeViolation(metaclass=abc.ABCMeta):
    def __init__(self, module: types.ModuleType, node: ast.AST) -> None:
        self.module = module
        self.node = node

    def __str__(self):
        return f"Issue in module {self.module.__name__}: line {self.node.lineno}, col {self.node.col_offset}"


class UnrequiredVersionableUsage(CodeViolation):
    def __init__(
        self,
        module: types.ModuleType,
        node: ast.AST,
        consuming_class: str,
        versionable_item_class: str,
    ) -> None:
        super().__init__(module, node)
        self.consuming_class = consuming_class
        self.versionable_item_class = versionable_item_class

    def __str__(self) -> str:
        return (
            super().__str__()
            + ": "
            + (
                f"Found usage of {self.versionable_item_class} "
                f"in class {self.consuming_class} that is not declared "
                f"in {self.consuming_class}'s `get_requirements()` classmethod"
            )
        )


class DirectVolatilityImportUsage(CodeViolation):
    def __init__(
        self,
        module: types.ModuleType,
        node: ast.AST,
        importing_module: str,
        imported_item: object,
        imported_name: str,
    ) -> None:
        self.imported_item = imported_item
        self.imported_name = imported_name
        self.importing_module = importing_module
        super().__init__(module, node)

    def __str__(self) -> str:
        components = self.importing_module.split(".")
        return (
            super().__str__()
            + ": "
            + (
                f"Direct import of {self.imported_name} "
                f"({type(self.imported_item)}) "
                f"from module {self.importing_module} - "
                "change to "
                f"'from {'.'.join(components[:-1])} import {components[-1]} and using {components[-1]}.{self.imported_name}"
            )
        )


def is_versionable(var):
    try:
        return (
            issubclass(var, interfaces.configuration.VersionableInterface)
            and var is not interfaces.configuration.VersionableInterface
            and not inspect.isabstract(var)
            and not (hasattr(var, "hidden") and getattr(var, "hidden") is True)
        )
    except TypeError:
        return False


def is_configurable(var):
    try:
        return issubclass(var, interfaces.configuration.ConfigurableInterface)
    except TypeError:
        return False


class ModuleVisitor(NodeVisitor):
    def __init__(self, module: types.ModuleType) -> None:
        self._module = module
        self._scopes = []
        self._violations = []

    @property
    def violations(self):
        return self._violations

    def _check_vol3_import_from(self, node: ast.ImportFrom):
        """
        Ensure that the only thing imported from a volatility3 module (apart
        from the root volatility3 module) are functions and modules. This
        prevents re-exporting of classes and variables from modules that use
        them.
        """
        if (
            node.module
            and node.module.startswith(
                "volatility3."
            )  # Give a pass to volatility3 module
            and node.module
            != "volatility3.framework.constants._version"  # make an exception for this
        ):
            for name in node.names:
                try:
                    item = vars(self._module)[
                        name.asname if name.asname is not None else name.name
                    ]
                except KeyError:
                    logger.debug(
                        "Couldn't find imported name %s in module %s",
                        name.asname or name.name,
                        self._module.__name__,
                    )
                    continue

                if not (isinstance(item, types.ModuleType) or inspect.isfunction(item)):
                    self._violations.append(
                        DirectVolatilityImportUsage(
                            self._module,
                            node,
                            node.module,
                            item,
                            name.asname or name.name,
                        )
                    )

    def enter_ImportFrom(self, node: ast.ImportFrom):
        self._check_vol3_import_from(node)

    def enter_ClassDef(self, node: ast.ClassDef) -> Any:
        logger.debug("Entering class %s", node.name)
        clazz = None
        try:
            clazz = vars(self._module)[str(node.name)]
        except KeyError:
            logger.debug(
                "Failed to get %s from module scope: (%s)",
                node.name,
                self._module.__name__,
            )
            if self._scopes:
                try:
                    logger.debug(
                        "Attempting to get class %s from scope of %s",
                        node.name,
                        self._scopes[-1].__name__,
                    )
                    clazz = getattr(self._scopes[-1], node.name)
                except AttributeError:
                    logger.debug(
                        "Class not found in scope of %s", self._scopes[-1].__name__
                    )
        if clazz:
            self._scopes.append(clazz)

        if clazz and is_configurable(clazz):
            logger.info("Checking configurable class %s", clazz.__name__)
            visitor = ConfigurableClassVisitor(self._module, clazz)
            visitor.visit(node)
            self._violations += visitor.violations

            self.generic_visit(node)

    def leave_ClassDef(self, node: ast.ClassDef):
        logger.debug("Leaving class %s", node.name)
        try:
            scoped_class = next(
                scope for scope in self._scopes if scope.__name__ == node.name
            )
            self._scopes.remove(scoped_class)
        except StopIteration:
            logger.debug("%s not found in scope list", node.name)


class ConfigurableClassVisitor(NodeVisitor):
    def __init__(
        self,
        module: types.ModuleType,
        clazz: Optional[Type[interfaces.configuration.ConfigurableInterface]],
    ) -> None:
        self._module = module
        self._current_object = None
        self._clazz = clazz
        self._seen = set()
        self._violations: List[CodeViolation] = []

    @property
    def versioned_classes(self):
        return (
            [
                req._component
                for req in self._clazz.get_requirements()
                if isinstance(req, configuration.requirements.VersionRequirement)
            ]
            if self._clazz is not None
            else []
        )

    def check_item(self, item: Type, node: Union[ast.Name, ast.Attribute]):
        if (
            is_versionable(item)
            and self._clazz is not None
            and item not in self.versioned_classes
            and item is not self._clazz
            and not issubclass(self._clazz, PluginRenameClass)
        ):
            logger.info(
                "Found versionable item %s, checking against %s",
                str(item),
                str(self.versioned_classes),
            )
            result = UnrequiredVersionableUsage(
                self._module, node, self._clazz.__name__, item.__name__
            )
            self._violations.append(result)

    @property
    def violations(self):
        return self._violations

    def visit_Name(self, node: ast.Name):
        try:
            logger.debug(
                "Checking module %s for name %s", self._module.__name__, node.id
            )
            item = vars(self._module)[str(node.id)]
            logger.debug("Found %s in %s namespace", node.id, self._module.__name__)
        except KeyError:
            return

        self.check_item(item, node)

    def visit_Attribute(
        self, node: ast.Attribute
    ) -> Optional[UnrequiredVersionableUsage]:
        if self._clazz is None:
            self.generic_visit(node)
            return

        if (node.lineno, node.col_offset) in self._seen:
            return

        self._seen.add((node.lineno, node.col_offset))

        stack = []
        root = node
        while True:
            stack.append(node.attr)
            if isinstance(node.value, ast.Attribute):
                node = node.value
            elif isinstance(node.value, ast.Name):
                stack.append(node.value.id)
                break
            else:
                break

        current = None
        logger.debug("Checking %s", ".".join(stack[::-1]))
        for item in stack[::-1]:
            try:
                current = (
                    vars(self._module)[item]
                    if current is None
                    else getattr(current, item)
                )
            except (KeyError, AttributeError) as exc:
                logger.debug(
                    "Failed to get attribute %s (%s)%s",
                    item,
                    exc.__class__.__name__,
                    (" on" + str(current)) if current is not None else "",
                )
                break

            self.check_item(current, root)


def report_missing_requirements() -> Iterator[Tuple[str, UnrequiredVersionableUsage]]:
    vol3 = importlib.import_module("volatility3")

    for _, module_name, _ in pkgutil.walk_packages(
        vol3.__path__, vol3.__name__ + ".", onerror=lambda _: None
    ):
        modname = module_name.replace(
            "volatility3.framework.plugins", "volatility3.plugins"
        )
        try:
            # import the module that we want to check
            plugin_module = importlib.import_module(modname)

        except ImportError as exc:
            logger.warning("Failed to import %s: %s", modname, str(exc))
            continue
        except Exception as exc:
            logger.warning(
                "An unexpected exception occurred while importing %s: %s",
                modname,
                str(exc),
            )
            traceback.print_exc()
            continue

        logger.info("Checking module %s", plugin_module.__name__)
        if plugin_module.__file__ is None:
            logger.warning("Plugin module %s has no source file", modname)
            continue

        try:
            with open(plugin_module.__file__, "rb") as f:
                source = f.read()
        except OSError:
            logger.warning(
                "Failed to read file contents for %s", plugin_module.__file__
            )
            continue

        try:
            module_ast_root = ast.parse(source)
        except (SyntaxError, ValueError) as exc:
            logger.warning(
                "Failed to parse source for %s: %s", plugin_module.__file__, str(exc)
            )
            raise

        mod_visitor = ModuleVisitor(plugin_module)
        mod_visitor.visit(module_ast_root)

        if mod_visitor.violations:
            yield from (
                (plugin_module.__name__, res) for res in iter(mod_visitor.violations)
            )


def perform_review():
    found = 0
    for mod, usage in report_missing_requirements():
        found += 1
        print(str(usage))

    if found:
        print(f"Found {found} issues")
        sys.exit(1)

    print("All configurable classes passed validation!")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="count", dest="verbosity", default=0)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.verbosity == 0:
        logger.setLevel(logging.WARNING)
    elif args.verbosity == 1:
        logger.setLevel(logging.INFO)
    elif args.verbosity > 1:
        logger.setLevel(logging.DEBUG)

    perform_review()
