#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import re
import sys
import json
import subprocess
from CScanScan import Coptions,CScanScan


class FindAssetsoptions(Coptions):
    def parameterFilter(self, ports):
        super(FindAssetsoptions, self).__init__()
        if self.options.inputfile == None:
            self.parser.error("options -inputfile can't be empty.")
        elif not os.path.exists(self.options.inputfile):
            self.parser.error("{0} no existed.".format(self.options.inputfile))
        if self.options.ports == None:
            self.options.ports = ",".join([str(port) for port in ports])
    def getoptions(self,ports):
        (self.options, _args) = self.parser.parse_args()
        self.parameterFilter(ports)
        return self.options


class FindSCA(CScanScan):
    '''
    发现服务组件
    '''
    def options(self):
        usage = '''"python %prog -i <inputfile> -p <ports> -h help"'''
        opt = FindAssetsoptions(usage)
        opt.p()
        opt.i()
        return opt.getoptions(self.CommonlyPorts)

    def getIpList(self, sourcefilename):
        try:
            sourcefile = open(sourcefilename,'r')
            source = json.load(sourcefile)
            ippattern = re.compile(r'((?:(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))\.){3}(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d)))')
            sourcefile.close()

            tmp = open("./iplist", 'w')
            tmp.write("\n".join(ippattern.findall(str(source))))
            tmp.close()
            return "./iplist"
        except Exception, e:
            sys.exit(e)

    def clearoutfile(self, outfile):
        if os.path.exists(outfile):
            with open(outfile, 'w') as f:
                f.truncate()

    def run(self, file, ports):
        try:
            file = self.getIpList(file)
            self.outfile = "tmp/SCA.json"
            self.clearoutfile(self.outfile)
            shell = "{nmapRun} -i {file} -p {ports} -oN {outfile} > /dev/null".format(nmapRun=self.RunPath, file=file, ports=ports, outfile=self.outfile)
            os.system(shell)
            os.remove(file)
        except Exception, e:
            sys.exit(e)

    def getResult(self):
        '''
        输出结构:
        {"SCA":[
            {"192.169.1.2":[
                {
                    "name":"http",
                    "port":80
                },{
                    "name":"mysql",
                    "port":3306
                }]},
            {"192.169.1.8":[
                {
                    "name":"http",
                    "port":80
                },{
                    "name":"ssh",
                    "port":22
                }]}
        ]}
        '''
        try:
            options = self.options()
            self.run(options.inputfile, options.ports)
            # 处理nmap输出信息~
            tmp = open(self.outfile, 'r')
            SCAInfo = tmp.readlines()
            tmplist = ''.join(SCAInfo).split("Nmap scan report for promote.cache-dns.local")
            result = {}
            SCA = []
            for ipyu in tmplist[1:]:
                ippattern = re.compile(r'((?:(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))\.){3}(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d)))')
                portpattern = re.compile(r'(\d+)/')
                namepattern = re.compile(r'open\s*(.*)\d*')
                
                ip = ippattern.findall(ipyu)[0]
                ipdict = {}
                portlist = []
                for portyu in ipyu.split("\n"):
                    if "open" in portyu:
                        portdict = {}
                        portdict["port"] = portpattern.findall(portyu)[0]
                        portdict["name"] = namepattern.findall(portyu)[0]
                        portlist.append(portdict)
                if portlist:
                    ipdict[ip] = portlist
                    SCA.append(ipdict)
            tmp.close()
            result["SCA"] = SCA
            return json.dumps(result, separators=(',', ':'))

        except Exception,e:
            sys.exit(e)

def main(runpath, outputFile):
    result = str(FindSCA(runpath).getResult())
    # 覆盖处理后信息~
    tmp = open(outputFile, "w")
    tmp.write(result)
    tmp.close()


if __name__ == '__main__':
    main("nmap/nmap", "tmp/SCA.json")