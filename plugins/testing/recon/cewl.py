#!/usr/bin/env python
# -*- coding: utf-8 -*-

__license__ = """
GoLismero 2.0 - The web knife - Copyright (C) 2011-2013

Authors:
  Daniel Garcia Garcia a.k.a cr0hn | cr0hn<@>cr0hn.com
  Mario Vilas | mvilas<@>gmail.com
  Daniel Maldonado | daniel_5502@yahoo.com.ar

Golismero project site: http://golismero-project.com
Golismero project mail: golismero.project<@>gmail.com

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

import shlex
import re

from os.path import join
from time import time
from traceback import format_exc

from golismero.api.config import Config
from golismero.api.data.resource.url import Url
from golismero.api.data.vulnerability.injection.sql import SQLInjection
from golismero.api.external import run_external_tool, find_binary_in_path, tempdir, tempfile, get_tools_folder
from golismero.api.logger import Logger
from golismero.api.net import ConnectionSlot
from golismero.api.net.web_utils import WEB_SERVERS_VARS
from golismero.api.plugin import TestingPlugin


#------------------------------------------------------------------------------
class CeWLTestingPlugin(TestingPlugin):


    #--------------------------------------------------------------------------
    def check_params(self):
        if not find_binary_in_path("cewl.rb"):
            raise RuntimeError(
                "CeWL not found!"
                " You can download it from: http://www.digininja.org/")


    #--------------------------------------------------------------------------
    def get_accepted_info(self):
        return [Url]


    #--------------------------------------------------------------------------
    def recv_info(self, info):

        # Get user args
        user_args = shlex.split(Config.plugin_args["args"])
        
        args = [info.url]
        user_args.extend(args)

        # Result info
        results = []

        with tempfile(suffix=".xml") as filename:

            # Run cewl
            if self.run_cewl(info.url, user_args):
                results.extend(filename)

        return results


    #--------------------------------------------------------------------------
    def run_cewl(self, url, args):
        """
        Run CeWL against the given target.

        :param url: The URL to be tested.
        :type url: str
        
        :param args: The arguments to pass to CeWL.
        :type args: list

        :return: True id successful, False otherwise.
        :rtype: bool
        """

        Logger.log("CeWL against: %s" % url)
        Logger.log_more_verbose("CeWL arguments: %s" % " ".join(args))

        cewl_script = join(get_tools_folder(), "cewl", "cewl.rb")

        with ConnectionSlot(url):
            t1 = time()
            code = run_external_tool(cewl_script, args, callback=Logger.log_verbose)
            t2 = time()

        if code:
            Logger.log_error("CeWL execution failed, status code: %d" % code)
            return False
        Logger.log("CeWL scan finished in %s seconds for target: %s" % (t2 - t1, url))
        return True
