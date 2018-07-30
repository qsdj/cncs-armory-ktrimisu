#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import re
import sys
import json
import logging
import subprocess
from CScanScan import Coptions, CScanScan


class FindAssetsoptions(Coptions):
    def parameterFilter(self, ports):
        super(FindAssetsoptions, self).__init__()
        # if self.options.inputfile == None:
        #     self.parser.error("options -inputfile can't be empty.")
        # elif not os.path.exists(self.options.inputfile):
        #     self.parser.error("{0} no existed.".format(self.options.inputfile))
        if self.options.ports == None:
            self.options.ports = ",".join([str(port) for port in ports])

    def getoptions(self, ports):
        (self.options, _args) = self.parser.parse_args()
        self.parameterFilter(ports)
        return self.options


class FindSCA(CScanScan):
    '''
    发现服务组件
    '''

    def options(self):
        usage = '''"python %prog -u <ip> -p <ports> -h help"'''
        opt = FindAssetsoptions(usage)
        opt.p()
        opt.u()
        return opt.getoptions(self.CommonlyPorts)

    def clearoutfile(self, outfile):
        if os.path.exists(outfile):
            with open(outfile, 'w') as f:
                f.truncate()

    def run(self, hosts, ports):
        try:
            self.outfile = "tmp/SCA.json"
            self.clearoutfile(self.outfile)
            shell = "{nmapRun} -p {ports} -oN {outfile} {hosts} > /dev/null".format(
                nmapRun=self.RunPath, ports=ports, outfile=self.outfile, hosts=hosts)
            print('run {}'.format(shell))
            os.system(shell)
        except Exception, e:
            logging.exception('nmap 扫描异常')
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
            self.run(options.hosts, options.ports)
            # 处理nmap输出信息~
            tmp = open(self.outfile, 'r')
            tmplist = tmp.readlines()
            tmp.close()

            result = {}
            SCA = []
            portpattern = re.compile(r'(\d+)/')
            namepattern = re.compile(r'open\s*(.*)\d*')
            for portyu in tmplist:
                if "open" in portyu:
                    port = portpattern.findall(portyu)[0]
                    name = namepattern.findall(portyu)[0]
                    if name is not None and port is not None:
                        result[name] = {'port': port}
            return json.dumps(result, separators=(',', ':'))

        except Exception, e:
            sys.exit(e)


def main(runpath, outputFile):
    result = str(FindSCA(runpath).getResult())
    # 覆盖处理后信息~
    tmp = open(outputFile, "w")
    tmp.write(result)
    tmp.close()
    print('RESULT_START')
    print(result)
    print('RESULT_END')


if __name__ == '__main__':
    if not os.path.exists('tmp'):
        os.makedirs('tmp')
    main("/usr/bin/nmap", "tmp/SCA.json")
