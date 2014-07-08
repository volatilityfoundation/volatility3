
import volatility.framework.interfaces.plugins as plugins

class pslist(plugins.PluginInterface):

    @classmethod
    def determine_inputs(cls):
        return {"primary":"Intel"}

