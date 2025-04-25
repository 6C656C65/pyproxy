"""
version.py

This module defines the version of the application. It contains a single constant
that holds the current version number of the application.

Constants:
- __version__: A string representing the current version of the application, 
  formatted as "major.minor.patch".
"""

import os

__version__ = "0.3.0"

if os.path.isdir("utils/proxy/monitoring"):
    __slim__ = False
else:
    __slim__ = True
