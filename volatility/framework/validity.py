'''
Created on 4 May 2013

@author: mike
'''

class ValidityRoutines(object):
    """Class to hold all validation routines, such as type checking"""

    def type_check(self, value, valid_type):
        """Checks that value is an instance of valid_type, and returns value if it is, or throws a TypeError otherwise"""
        if not isinstance(value, valid_type):
            raise TypeError(self.__class__.__name__ + " expected " + valid_type.__class__.__name__ + ", not " + type(value))
        return value

    def confirm(self, assertion, error):
        """Acts like an assertion, but will not be disabled when __debug__ is disabled"""
        if not assertion:
            if error is None:
                error = "An unspecified Assertion was not met"
            raise AssertionError(error)
