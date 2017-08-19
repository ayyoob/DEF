
import abc
import logging
""" Abstract Attack Definition.
"""
log = logging.getLogger(__name__)

class GenericAttack(object):

    __metaclass__ = abc.ABCMeta

    def __init__(self, attackName, attackConfig, deviceConfig):
        # meta
        self.config = attackConfig          # dictionary of a module's config
        self.attackName = attackName  # who or what are we?
        self.device = deviceConfig
        self.running = False

    @abc.abstractmethod
    def initialize(self):
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
