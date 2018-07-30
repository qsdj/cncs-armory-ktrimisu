#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import re
import sys
import json
import subprocess
from CScanScan import Coptions, CScanScan


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
                            ipportlist.append(
                                ipyu.keys()[0]+":"+service["port"])
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

            shell = "{whatWebRun} -i {file} --log-json {outfile} > /dev/null".format(
                whatWebRun=self.RunPath, file=file, outfile=self.outfile)
            os.system(shell)
            os.remove(file)
        except Exception, e:
            sys.exit(e)

    def getResult(self):
        '''
        result  = {
            "target":{
                "product_name":{
                    "version":"version",
                    'deploy_path': 'defaultDeploy_path',
                    'home_page': 'defaultHome_page',
                    'pl': 'plname',
                    'pl_version': 'pl_versionInfo',
                },
                "webServerName":{
                    "version":"versionInfo"
                },
                'http': {
                    'port': 80
                    }
            }
        }'''
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
                    ip_port = ipyu["target"].split("//")[1]
                    if ":" in ip_port:
                        ip = ip_port.split(":")[0]
                        port = int(ip_port.split(":")[1])
                    elif "/" in ip_port:
                        ip = ip_port.split("/")[0]
                        port = 80
                        home_page = "/" + ip_port.split("/")[1]
                    plugins["http"] = {"port": port}
                    product_name = ""

                    ipyuKeys = ipyu["plugins"].keys()
                    if "HTTPServer" in ipyuKeys:
                        if " " in ipyu["plugins"]["HTTPServer"]["string"][0]:
                            httpserverinfo = ipyu["plugins"]["HTTPServer"]["string"][0].split(" ")[0]
                        else:
                            httpserverinfo = ipyu["plugins"]["HTTPServer"]["string"][0]
                        if "/" in httpserverinfo:
                            webServerName = httpserverinfo.split('/')[0]
                            plugins[webServerName] = {}
                            plugins[webServerName]["version"] = httpserverinfo.split('/')[1]

                        else:
                            webServerName = httpserverinfo.split('/')[0]
                            plugins[webServerName] = {}

                    if "MetaGenerator" in ipyuKeys:
                        if " " in ipyu["plugins"]["MetaGenerator"]["string"][0]:
                            productinfo = ipyu["plugins"]["MetaGenerator"]["string"][0]
                            product_name = productinfo.split(" ")[0]
                            plugins[product_name] = {}
                            plugins[product_name]["version"] = productinfo.split(" ")[1]
                            try:
                                plugins[product_name]["home_page"] = home_page
                            except:
                                pass
                            plugins[product_name]["deploy_path"] = "/"

                        else:
                            product_name = ipyu["plugins"]["MetaGenerator"]["string"][0]
                            plugins[product_name] = {}
                            plugins[product_name]["deploy_path"] = "/"

                    if "X-Powered-By" in ipyuKeys:
                        if product_name == "":
                            product_name = "web"
                            plugins[product_name] = {}
                        if "/" in ipyu["plugins"]["X-Powered-By"]["string"][0]:
                            plugins[product_name]["pl_version"] = ipyu["plugins"]["X-Powered-By"]["string"][0].split('/')[1]
                            plugins[product_name]["pl"] = ipyu["plugins"]["X-Powered-By"]["string"][0].split('/')[0]
                        else:
                            plugins[product_name]["pl"] = ipyu["plugins"]["X-Powered-By"]["string"][0]

                    target[ip] = plugins
                    WhatWeb.append(target)

            result["whatweb"] = WhatWeb
            tmp.close()
            return json.dumps(result, separators=(',', ':'))

        except Exception, e:
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
