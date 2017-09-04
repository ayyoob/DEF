
import abc
import logging
import os
from re import search
from subprocess import Popen
from commands import getoutput
import time
""" Abstract Attack Definition.
"""
log = logging.getLogger(__name__)

class ReportGenerator(object):

    __metaclass__ = abc.ABCMeta

    def __init__(self, attackConfig, deviceConfig, result):
        if attackName is None and attackConfig is None and deviceConfig is None:
            pass
        # meta
        self.config = attackConfig
        self.device = deviceConfig
        self.result =result


    def generate(self):
        pass

