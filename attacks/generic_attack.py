
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

class GenericAttack(object):

    __metaclass__ = abc.ABCMeta

    def __init__(self, attackName, attackConfig, deviceConfig):
        if attackName is None and attackConfig is None and deviceConfig is None:
            pass
        # meta
        self.config = attackConfig          # dictionary of a module's config
        self.attackName = attackName  # who or what are we?
        self.device = deviceConfig
        self.running = False

    @abc.abstractmethod
    def initialize(self, result):
        """Initialization method that should be
           implemented at the module level
        """
        raise NotImplementedError


    def shutdown(self):
        """ Shut down the module cleanly
        """
        log.debug('Shutting \'%s\' down..' % self.attackName)

        if self.running:
            self.running = False

        log.debug("%s shutdown." % self.attackName)

    def isCompleted(self):
        return not self.running

    def prerequisite(self):
        return None

    def is_alive(self):
        """Check if the target is alive"""
        if not self.device['ip'] is None:
            rval = self.init_app('ping -c 1 -w 1 %s' % \
                            self.device['ip'], True)
            up = search('\d.*? received', rval)
            if search('0', up.group(0)) is None:
                return True
        return False

    def init_app(self, prog, output=True):
        """inititalize an application
           PROG is the full command with args
           OUTPUT true if output should be returned
           false if output should be dumped to null.  This will
           return a process handle and is meant for initializing
           background processes.  Use wisely.
        """
        # dump output to null
        if not output:
            try:
                null = open(os.devnull, 'w')
                proc = Popen(prog, stdout=null, stderr=null)
            except Exception, j:
                log.error("Error initializing app: %s" % j)
                return False
            return proc
        # just grab output
        else:
            return getoutput(prog)

    def retry_is_alive(self, maxRetry=5, sleep=0.5):
        retryCount = 0
        while (not self.is_alive()):
            retryCount = retryCount + 1
            time.sleep(sleep)
            if retryCount == maxRetry:
                return False

        return True