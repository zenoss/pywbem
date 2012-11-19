'''A pure-Python library for performing operations using the WBEM
management protocol.'''

#
# (C) Copyright 2004 Hewlett-Packard Development Company, L.P.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; version 2 of the License.
#   
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#   
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

# Author: Tim Potter <tpot@hp.com>

# Version 0.8.x are changes made by the Zenoss Labs Team.
#

#0.8.1
#Due to a serious performance hit on memory the minidom was replaced with
#the Python C library cElementTree. This allows better handling of memory and
#increased the performance on the results returned.
#Also, The ExecQuery method was added to support CQL calls via WBEM.
#
# 0.8.0
#Cleaned up twisted_client. It was not working in the deployed state.
#Made several modifications to the methods to correctly use twisted.

from distutils.core import setup, Extension
import sys, string, os
import shutil

import mof_compiler
mof_compiler._build()

args = {'name': 'pywbem',
        'author': 'Tim Potter',
        'author_email': 'tpot@hp.com',
        'description': 'Python WBEM client library',
        'long_description': __doc__,
        'platforms': ['any'],
        'url': 'http://pywbem.sf.net/',
        'version': '0.8.1',
        'license': 'LGPLv2',
        'packages': ['pywbem'],
        # Make packages in root dir appear in pywbem module
        'package_dir': {'pywbem': ''}, 
        # Make extensions in root dir appear in pywbem module
        'ext_package': 'pywbem',
        }

setup(**args)
