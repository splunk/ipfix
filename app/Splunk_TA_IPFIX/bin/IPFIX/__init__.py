#!/usr/bin/env python
__author__ = 'Joel Bennett'

from os import path

MODULE_PATH = path.abspath(path.dirname(__file__))
TEMPLATE_PATH = path.abspath(path.join(MODULE_PATH, 'information-elements'))

from IPFIXParser import *
__all__ = ["Parser", "MODULE_PATH", "TEMPLATE_PATH"]
