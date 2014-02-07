__author__ = 'JBennett'
#
# RelaxNG validator utility
#
# This script will validate every XML file found inside of the current Splunk
# instance's /etc/apps directory
#
# See README.txt for setup information
#

import lxml.etree as et
import os, re
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path


FOLDER = os.path.dirname(os.path.abspath(__file__))

f = open(os.path.join(FOLDER,'../_support/ipfix.rng'), 'r')
schema = et.parse(f)
relaxng = et.RelaxNG(schema)
f.close()

for root, dirs, files in os.walk(FOLDER):
    for name in files:
        if name.endswith('.xml'):
            print '=' * 80
            print "Validating file: %s" % os.path.join(root, name)
            f = open(os.path.join(root, name), 'r')
            rootNode = et.parse(f)
            isValid = relaxng.validate(rootNode)
            if not isValid:
                print "Validation error: %s" % name
                print relaxng.error_log
                print ''
            else:
                print "Valid file: %s" % name
            f.close()
