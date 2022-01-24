# EdgeVPNio
# Copyright 2020, University of Florida
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import os
import threading
import types
from collections import namedtuple
import time
from framework.ControllerModule import ControllerModule
import framework.Modlib as Modlib
from distutils import spawn
from socket import AF_INET
from pyroute2 import IPRoute
from pyroute2 import NDB

class GeneveTunnel(ControllerModule):
    
    def __init__(self, cfx_handle, module_config, module_name):
        super(GeneveTunnel, self).__init__(cfx_handle, module_config, module_name)
        self.ipr = IPRoute()
        self.ndb = NDB()

    # def _create_vxlan_tunnel(self, remote, gateway_dev_name, dst_port, dev_name, vlid):
    #     #self.ndb.interfaces.create(ifname=dev_name, kind=tnl_type, )
    #     self.ipr.link("add",
    #                   kind="vxlan",
    #                   ifname=dev_name,
    #                   vxlan_link=self.ip.link_lookup(ifname=gateway_dev_name)[0],
    #                   vxlan_id=101,
    #                   vxlan_group='239.1.1.1',
    #                   vxlan_ttl=16
    #                   )        
        # cmd = [GeneveTunnel.iptool, 
        #                  "link","add",
        #                  "type", tnl_type,
        #                  "id", vlid,
        #                  "remote", remote,
        #                  "dstport", dst_port,
        #                  "dev", dev]
        # Modlib.runshell(cmd)
        
    def _create_geneve_tunnel(self, dev_name, id, remote_addr, dst_port=None):
        self.ipr.link("add",
                ifname=dev_name,
                kind="geneve",
                geneve_id=id,
                geneve_remote=remote_addr)        
        
    def _del_tunnel(self, dev_name):
        #ip = IPRoute()
        self.ipr.link("del", index=self.ip.link_lookup(ifname=dev_name)[0])
        # cmd = [GeneveTunnel.iptool, 
        #                  "link","del",
        #                  "dev", dev]
        # Modlib.runshell(cmd)
        
    def _is_tunnel_exist(self):
        return False
    
    def req_handler_create_tunnel(self, cbt):
        tnl_type = cbt.request.params["TunnelType"]
        remote_addr = cbt.request.params["RemoteAddr"]
        dst_port = cbt.request.params["DstPort"]
        dev_name = cbt.request.params["DeviceName"]
        vlid = cbt.request.params["VxLanID"]
        if not self._is_tunnel_exist():    
            self.__create_vxlan_tunnel(tnl_type, remote_addr, dst_port, dev_name, vlid)
            cbt.response.set_response(data=f"Tunnel {dev_name} created", status=True)
        else:
            cbt.set_response(data=f"Tunnel {dev_name} already exist", status=False)
    
    def req_handler_remove_tunnel(self, cbt):
        dev_name = cbt.request.params["DeviceName"]
        self._del_tunnel(dev_name)
        cbt.response.set_response(data=f"Tunnel {dev_name} deleted", status=True)
    
    def process_cbt(self, cbt):
        if cbt.op_type == "Request":
            if cbt.request.action == "TMN_CREATE_TUNNEL":
                self.req_handler_create_tunnel(cbt)
            elif cbt.request.action == "TMN_REMOVE_TUNNEL":
                self.req_handler_remove_tunnel(cbt)

            else:
                self.req_handler_default(cbt)
        elif cbt.op_type == "Response":
            self.free_cbt(cbt)

def _create_geneve_tunnel(dev_name, id, remote_addr, dst_port=None):
    ipr = IPRoute()
    ipr.link("add",
            ifname=dev_name,
            kind="geneve",
            geneve_id=id,
            geneve_remote=remote_addr)
    print("Geneve tunnel created")      
    
def _del_tunnel(self, dev_name):
    ipr = IPRoute()
    ipr.link("del", index=self.ip.link_lookup(ifname=dev_name)[0])
    
def unittest():
    _create_geneve_tunnel("gentun", 2236, "192.168.0.92")
    

if __name__ == "__main__":
    unittest()