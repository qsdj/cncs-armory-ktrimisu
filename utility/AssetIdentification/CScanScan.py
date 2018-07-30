#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import optparse


class Coptions(object):
    def __init__(self, usage=None):
        if usage == None:
            usage = '''"python %prog -h | --help"'''
        self.parser = optparse.OptionParser(usage)

    def u(self):
        self.parser.add_option('-u', dest='hosts', type='string',
                               help=u'''请输入 IP 地址段，1.1.1.1-1.1.1.x''')

    def p(self):
        self.parser.add_option('-p', dest='ports', type='string',
                               help=u'''请输入端口号(不选：扫常用端口)''')

    def r(self):
        self.parser.add_option('-r', dest='rate', type='int',
                               help=u'''(masscan)请设置扫描并发率 (并发率越高扫描的精度越低,默认1000)''')

    def i(self):
        self.parser.add_option('-i', dest='inputfile', type='string',
                               help=u'''请输入文件名()''')

    def parameterFilter(self):
        '''
        参数过滤，处理
        '''
        pass

    def getoptions(self):
        (self.options, _args) = self.parser.parse_args()
        self.parameterFilter()
        return self.options


class CScanScan(object):
    def __init__(self, runpath):
        '''
        runpath::: (相对|绝对)路径
        '''
        if runpath.endswith("/"):
            sys.exit("[{0}]期望文件而不是目录".format(runpath))
        if runpath.startswith("/"):
            self.RunPath = runpath
        else:
            self.BASEDIR = os.path.dirname(os.path.abspath(__file__))
            self.RunPath = os.path.join(self.BASEDIR, runpath)

        if not os.path.exists(self.RunPath):
            sys.exit("[{0}]不存在".format(self.RunPath))
        # 设置常用端口以便发现资产
        self.CommonlyPorts = set([21, 22, 23, 25, 53, 69, 80, 110, 443, 1080, 1158,
                                  1433, 1521, 2100, 3128, 3306, 3389, 5000, 7001, 8000, 8080, 8081, 9080, 9090])

    def options(self, usage=None):
        pass

    def run(self, hosts, ports, rate):
        pass

    def getResult(self):
        pass
