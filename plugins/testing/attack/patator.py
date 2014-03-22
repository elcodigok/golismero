#!/usr/bin/env python
# -*- coding: utf-8 -*-

__license__ = """
GoLismero 2.0 - The web knife - Copyright (C) 2011-2013

Authors:
  Daniel Maldonado | daniel_5502<@>yahoo.com.ar
  Daniel Garcia Garcia a.k.a cr0hn | cr0hn<@>cr0hn.com
  Mario Vilas | mvilas<@>gmail.com

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
from time import time
from os.path import join

from golismero.api.config import Config
from golismero.api.data.resource.domain import Domain
from golismero.api.data.resource.url import URL
from golismero.api.data.resource.ip import IP
from golismero.api.data.information.fingerprint import ServiceFingerprint
from golismero.api.data.information.portscan import Portscan
from golismero.api.external import run_external_tool, tempfile, find_binary_in_path, get_tools_folder
from golismero.api.logger import Logger
from golismero.api.net import ConnectionSlot
from golismero.api.plugin import TestingPlugin
from golismero.api.data import Relationship
from golismero.api.text.wordlist import WordListLoader


#------------------------------------------------------------------------------
class PatatorPlugin(TestingPlugin):


    #--------------------------------------------------------------------------
    def check_params(self):
        if not find_binary_in_path("patator_v0.5.py"):
            raise RuntimeError(
                "Patator not found! You can download it from:"
                " https://code.google.com/p/patator/")


    #--------------------------------------------------------------------------
    def get_accepted_types(self):
        return [Relationship(IP, ServiceFingerprint), Relationship(IP, Portscan)]


    #--------------------------------------------------------------------------
    def run(self, info):

        # Get user args
        #user_args = shlex.split(Config.plugin_args["args"])
        path_password = WordListLoader.get_wordlist(Config.plugin_args["password"])

        if info[0].is_instance(IP):
            Logger.log(info[0])
            Logger.log("Es una instancia de IP")
            pass # hacer algo con la IP
        elif info[0].is_instance(Domain):
            Logger.log("No es una instancia de IP")
            pass # si entra aqui es un Domain en vez de IP

        if info[1].is_instance(ServiceFingerprint):
            Logger.log("Es una instancia de ServiceFingerprint")
            Logger.log(info[1])
        elif info[1].is_instance(Portscan):
            Logger.log("Es un Portscan")
            #Logger.log(info[1].ports)
            #Logger.log(info[1].address)
            for service in info[1].ports:
                Logger.log(service[2])
                if service[2] == 22:
                    args = [
                        "ssh_login",
                        "host=%s" % (info[0]), 
                        "port=22",
                        "user=root",
                        "password=FILE0",
                        "0=%s" % ("wordlist/" + Config.plugin_args["password"])
                    ]
                    Logger.log(args)
                    Logger.log("Patator against: %s" % info[1].address)
                    Logger.log_more_verbose("Patator arguments: %s" % " ".join(args))
 
                    patator_script = join(get_tools_folder(), "patator", "patator_v0.5.py")
 
                    with ConnectionSlot(info[1].address):
                        t1 = time()
                        code = run_external_tool(patator_script, args, callback=Logger.log_verbose)
                        t2 = time()

        return
