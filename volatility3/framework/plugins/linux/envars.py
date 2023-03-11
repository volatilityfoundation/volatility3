from volatility3.plugins import envvars
import logging

vollog = logging.getLogger(__name__)


class Envars(envvars.Envvars):
    def run(self, *args, **kwargs):
        vollog.warning(
            "The linux.envars plugin has been renamed to linux.envvars and will only be accessible through the new name in a future release"
        )
        return super().run(*args, **kwargs)
