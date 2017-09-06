import abc
import logging

from lib import html

""" Abstract Attack Definition.
"""
log = logging.getLogger(__name__)

class ReportGenerator(object):

    __metaclass__ = abc.ABCMeta

    def __init__(self, attackConfig, deviceConfig, result):
        # meta
        self.config = attackConfig
        self.device = deviceConfig
        self.result =result



    def generate(self):
        filename = 'results/' + self.device['time'] + '/device_result.html'
        f = open(filename, 'w')
        result=self.result
        deviceConfig=self.device
        header = ['Mac Address'] + result.keys()
        values = []
        values.append(deviceConfig['macAddress'])
        for x in result.keys():
            if result[x]["result"] is not None:
                val = '\n'.join('{}: {}'.format(key, val) for key, val in result[x]["result"].items())
            else:
                val = ""
            values.append(val)
        table_data = [
            header,
            values
        ]
        htmlcode = html.table(table_data)
        print htmlcode
        f.write(htmlcode)
        f.write('<p>')
        print '-' * 79

        f.close()
        log.info('\nOpen the file %s in a browser to see the result.' % filename)

