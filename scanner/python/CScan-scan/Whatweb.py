#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import re
import sys
import json
import subprocess
from CScanScan import Coptions,CScanScan


class FindAssetsoptions(Coptions):
    def parameterFilter(self):
        super(FindAssetsoptions, self).__init__()
        if self.options.inputfile == None:
            self.parser.error("options -inputfile can't be empty.")
        elif not os.path.exists(self.options.inputfile):
            self.parser.error("{0} no existed.".format(self.options.inputfile))

    def getoptions(self):
        (self.options, _args) = self.parser.parse_args()
        self.parameterFilter()
        return self.options


class WhatWeb(CScanScan):
    '''
    发现 服务提供组件/应用组件
    '''
    def options(self):
        usage = '''"python %prog -i <inputfile> -h help"'''
        opt = FindAssetsoptions(usage)
        opt.i()
        return opt.getoptions()

    def getIpList(self, sourcefilename):
        try:
            sourcefile = open(sourcefilename, 'r')
            source = json.load(sourcefile)
            sourcefile.close()

            tmp = open("./iplist", 'w')
            ipportlist = []
            for ipyu in source["SCA"]:
                for allservice in ipyu.values():
                    for service in allservice:
                        if "http" in service["name"]:
                            ipportlist.append(ipyu.keys()[0]+":"+service["port"])
            tmp.write("\n".join(ipportlist))
            tmp.close()
            return "./iplist"
        except Exception, e:
            sys.exit(e)

    def clearoutfile(self, outfile):
        if os.path.exists(outfile):
            with open(outfile, 'w') as f:
                f.truncate()

    def run(self, file):
        try:
            file = self.getIpList(file)
            self.outfile = "tmp/Whatweb.json"
            self.clearoutfile(self.outfile)

            shell = "{whatWebRun} -i {file} --log-json {outfile} > /dev/null".format(whatWebRun=self.RunPath, file=file, outfile=self.outfile)
            os.system(shell)
            os.remove(file)
        except Exception, e:
            sys.exit(e)

    def getResult(self):
        '''
        输出结构:
        {
            "whatweb":[
                {"http://192.168.1.1:80":{
                    "Boa-WebServer": {
                    "version": ["0.94.13"]
                    },
                    "HTTPServer": {
                        "string": ["Boa/0.94.13"]
                    },
                    "Script": {
                        "string": ["javascript>top.location.replace("]
                    }
                }
                },{"http://192.168.1.1:8080":{
                    
                }
                }
            ]
        }
        '''
        try:
            options = self.options()
            self.run(options.inputfile)
            # 处理nmap输出信息~
            tmp = open(self.outfile, 'r')
            WhatwebInfo = json.load(tmp)
            result = {}
            WhatWeb = []
            for ipyu in WhatwebInfo:
                if not ipyu == {}:
                    target = {}
                    plugins = {}
                    for name in ipyu["plugins"].keys():
                        if name != "Country" and name != "IP" and name!= "UncommonHeaders" and name!= "Title" and name != "Cookies" and ipyu["plugins"][name]!= {}:
                            plugins[name] = ipyu["plugins"][name]
                    target[ipyu["target"]] = plugins
                    WhatWeb.append(target)
            result["whatweb"] = WhatWeb
            tmp.close()
            return json.dumps(result, separators=(',', ':'))

        except Exception,e:
            sys.exit(e)

def main(runpath, outputFile):
    result = str(WhatWeb(runpath).getResult())
    # 覆盖处理后信息~
    tmp = open(outputFile, "w")
    tmp.write(result)
    tmp.close()

def test():
    # WhatWeb("WhatWeb/whatweb").run("./tmp/SCA.json")
    pass



if __name__ == '__main__':
    main("WhatWeb/whatweb", "tmp/Whatweb.json")