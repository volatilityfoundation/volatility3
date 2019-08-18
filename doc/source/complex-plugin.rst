Writing more advanced Plugins
=============================

There are several common tasks you might wish to accomplish, there is a recommended means of achieving most of these
which are discussed below.

Writing Reusable Methods
------------------------
Classes which inherit from :py:class:`~volatility.framework.interfaces.plugins.PluginInterface` all have a :py:method:`run` method
which takes no parameters and will return a :py:class:`~volatility.framework.interfaces.renderers.TreeGrid`.  Since most useful
functions are parameterized, to provide parameters to a plugin the `configuration` for the context must be appropriately manipulated.
There is scope for this, in order to run multiple plugins (see `Writing plugins that run other plugins`) but a much simpler method
is to provide a parameterized `classmethod` within the plugin, which will allow the method to yield whatever kind of output it will
generate and take whatever parameters it might need.

This is how processes are listed, which is an often used function.  The code lives within the pslist plugin but can be used by
other plugins by providing the appropriate parameters (see :py:method:`list_processes`).

It is up to the author of a plugin to validate that any required plugins are present and are the appropriate version.

Writing plugins that run other plugins
--------------------------------------


Writing Scanners
----------------

Writing Intermediate Symbol Format Files
----------------------------------------
