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

from golismero.api.config import Config
from golismero.api.data.resource.domain import Domain
from golismero.api.data.resource.ip import IP
from golismero.api.data.information.fingerprint import ServiceFingerprint
from golismero.api.data.information.portscan import Portscan
from golismero.api.external import run_external_tool, tempfile, \
    find_binary_in_path, get_tools_folder
from golismero.api.logger import Logger
from golismero.api.net import ConnectionSlot
from golismero.api.plugin import TestingPlugin
from golismero.api.data import Relationship


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
        return Relationship(IP, ServiceFingerprint),Relationship(Domain, ServiceFingerprint), Relationship(IP, Portscan), Relationship(Domain, Portscan)


    #--------------------------------------------------------------------------
    def get_accepted_info(self):
        return [IP, Domain]


    #--------------------------------------------------------------------------
    def recv_info(self, info):
        Logger.log(info)
        if info[0].is_instance(IP):
            Logger.log(info[0].version)
            Logger.log("Es una instancia de IP")
            pass # hacer algo con la IP
        else:
            Logger.log("No es una instancia de IP")
            pass # si entra aqui es un Domain en vez de IP

        if info[1].is_instance(ServiceFingerprint):
            Logger.log("Es una instancia de ServiceFingerprint")
            pass # hacer algo con el servicio
        else:
            Logger.log("No es una instancia de ServiceFingerprint")
            pass #si entra aqui es un Portscan
