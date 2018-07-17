#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
from CScanScan import Coptions

class Mainoptions(Coptions):
    def parameterFilter(self, ports):
        super(Mainoptions, self).__init__()
        if self.options.hosts == None:
            self.parser.error("options -host can't be empty")
        if self.options.rate == None:
            self.options.rate = 1000
        if self.options.rate > 1500000:
            self.parser.error("max rate is 1500000")
        if self.options.ports == None:
            self.options.ports = ",".join([str(port) for port in ports])
    
    def getoptions(self,ports):
        (self.options, _args) = self.parser.parse_args()
        self.parameterFilter(ports)
        return self.options

def main():
    usage = '''"python %prog -u <hosts> -p <ports> -r <rate> -h help"'''
    opt = Mainoptions(usage)
    opt.u()
    opt.p()
    opt.r()
    options = opt.getoptions(set([21, 22, 23, 25, 53 ,69, 80, 110, 443, 1080, 1158, 1433, 1521, 2100, 3128, 3306, 3389, 5000, 7001, 8000, 8080, 8081, 9080, 9090]))
    
    FindAssetsShell = "python FindAssets.py -u {} -p {} -r {}".format(options.hosts, options.ports, options.rate)
    FindSCAShell = "python FindSCA.py -i tmp/Assets.json -p {}".format(options.ports)
    WhatwebShell = "python Whatweb.py -i tmp/SCA.json"
    
    os.system(FindAssetsShell)
    os.system(FindSCAShell)
    os.system(WhatwebShell)

if __name__ == "__main__":
    main()