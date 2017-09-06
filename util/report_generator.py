import abc
import logging

from lib import html

""" Abstract Attack Definition.
"""
log = logging.getLogger(__name__)

class ReportGenerator(object):

    __metaclass__ = abc.ABCMeta

    def __init__(self, attackConfig, results, time):
        # meta
        self.config = attackConfig
        self.results =results
        self.time = time

    def generate(self):
        filename = 'results/' + self.time + '/device_result.html'
        f = open(filename, 'w')
        header = ['Mac Address']
        header.extend(self.config['attack'])

        table_data = [header]
        resultLen = len(self.results)
        for deviceResult in self.results:

            value = []
            value.append(deviceResult['macAddress'])
            result = deviceResult['attacks']
            for x in result.keys():
                if result[x]["result"] is not None:
                    val = '\n'.join('{}: {}'.format(key, val) for key, val in result[x]["result"].items())
                else:
                    val = ""
                value.append(val)
            table_data.append(value)

        htmlcode = html.table(table_data)
        print htmlcode
        f.write(htmlcode)
        f.write('<p>')
        print '-' * 79

        f.close()
        log.info('\nOpen the file %s in a browser to see the result.' % filename)

