from volatility3 import framework
from volatility3.framework import interfaces


class LinuxUtilityInterface(interfaces.configuration.VersionableInterface):
    """Class with multiple useful linux functions surrounding a specific piece of functionality."""

    _version = (2, 1, 1)
    _required_framework_version = (2, 0, 0)

    framework.require_interface_version(*_required_framework_version)

    @classmethod
    def get_module_from_volobj_type(
        cls,
        context: interfaces.context.ContextInterface,
        volobj: interfaces.objects.ObjectInterface,
    ) -> interfaces.context.ModuleInterface:
        """Get the vmlinux from a vol obj

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            volobj (vol object): A vol object

        Raises:
            ValueError: If it cannot obtain any module from the symbol table

        Returns:
            A kernel object (vmlinux)
        """
        symbol_table = volobj.get_symbol_table_name()
        module_names = context.modules.get_modules_by_symbol_tables(symbol_table)
        module_names = list(module_names)

        if not module_names:
            raise ValueError(f"No module using the symbol table '{symbol_table}'")

        kernel_module_name = module_names[0]
        kernel = context.modules[kernel_module_name]

        return kernel
