"""
A simple testing suite
"""
import poc_simpletest
import utils

def run_test():
    """
    Tests for verifying functions
    """
    # create a TestSuite object
    suite = poc_simpletest.TestSuite()

    ##run tests

    #test fermat
    sre = utils.valid_username('stijn')

    suite.run_test('stijn' and sre, sre, 'test')

    # report number of tests and failures
    suite.report_results()

run_test()
