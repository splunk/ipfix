__author__ = 'JBennett'

#!/usr/bin/env python
__author__ = 'Joel Bennett'
import logging
import logging.handlers

__all__ = ['SplunkLogger']


class SplunkLogger(logging.Logger):
    """
    Class for generating and rotating logs for Splunk app.
    """
    def __init__(self, fileName, max_bytes, backup_count, level=logging.INFO):
        super(SplunkLogger, self).__init__(__name__, level)
        # self.logger = logging.getLogger(__name__)
        # self.logger.setLevel(level)
        handler = logging.handlers.RotatingFileHandler(fileName, maxBytes=max_bytes, backupCount=backup_count)
        self.addHandler(handler)


def test():
    print 'SplunkLogger class testing:'
    logger = SplunkLogger('./test.log', 1024, 5)
    print 'outputting to logfile => {}'.format(logger.handlers[0].baseFilename)
    for i in range(2000):
        logger.info('This is a test %d' % i)
    print 'Finished testing!'

if __name__ == '__main__':
    test()
