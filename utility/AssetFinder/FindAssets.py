#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import re
import sys
import json
import subprocess
from CScanScan import Coptions, CScanScan


class FindAssetsoptions(Coptions):
    def parameterFilter(self, ports):
        super(FindAssetsoptions, self).__init__()
        if self.options.hosts == None:
            self.parser.error("options -host can't be empty")
        if self.options.rate == None:
            self.options.rate = 1000
        if self.options.rate > 1500000:
            self.parser.error("max rate is 1500000")
        if self.options.ports == None:
            self.options.ports = ",".join([str(port) for port in ports])

    def getoptions(self, ports):
        (self.options, _args) = self.parser.parse_args()
        self.parameterFilter(ports)
        return self.options


class FindAssets(CScanScan):
    '''
    发现资产
    '''

    def options(self):
        usage = '''"python %prog -u <hosts> -p <ports> -r <rate> -h help"'''
        opt = FindAssetsoptions(usage)
        opt.u()
        opt.p()
        opt.r()
        return opt.getoptions(self.CommonlyPorts)

    def clearoutfile(self, outfile):
        os.makedirs('tmp')
        if os.path.exists(outfile):
            with open(outfile, 'w') as f:
                f.truncate()

    def run(self, hosts, ports, rate):
        try:
            self.outfile = "tmp/Assets.json"
            self.clearoutfile(self.outfile)
            shell = "{masscanRun} {hosts} -p {ports} --rate {rate} -oL {outfile} > /dev/null".format(
                masscanRun=self.RunPath, hosts=hosts, ports=ports, rate=rate, outfile=self.outfile)
            os.system(shell)
        except Exception, e:
            sys.exit(e)

    def getResult(self):
        '''
        输出结构:
        {
            "assets":[
                "192.168.1.1",
                "192.168.1.2",
                "192.168.1.3"
            ]
        }
        '''
        try:
            ippattern = re.compile(
                r'((?:(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))\.){3}(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d)))')
            options = self.options()
            self.run(options.hosts, options.ports, options.rate)
            # 处理masscan输出信息~
            result_file = open(self.outfile, 'r')
            iplist = set(ippattern.findall(str(result_file.readlines())))
            result_file.close()
            if iplist:
                result = {}
                result["assets"] = list(iplist)
                return json.dumps(result, separators=(',', ':'))
            else:
                sys.exit("未扫描到资产")
        except Exception, e:
            sys.exit(e)


def main(runpath, outputFile):
    result = str(FindAssets(runpath).getResult())
    # 覆盖整理信息~
    tmp = open(outputFile, "w")
    tmp.write(result)
    tmp.close()
    sys.stdout.flush()
    print('RESULT_START')
    print(result)
    print('RESULT_END')
    sys.stdout.flush()


if __name__ == '__main__':
    main("masscan/masscan", "tmp/Assets.json")
