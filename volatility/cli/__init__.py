__author__ = 'mike'

import volatility.framework

class CommandLine():
    def __init__(self):
        pass

    def run(self):
        sys.stdout.write("Volatility Framework 3 (version "+ "{0}.{1}.{2}".format(volatility.framework.version()) + ")")

def main():
    CommandLine().run()