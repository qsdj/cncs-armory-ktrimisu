# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Info_PHPinfo'  # 平台漏洞编号，留空
    name = '敏感测试页面泄露'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        PHPInfo()函数主要用于网站建设过程中测试搭建的PHP环境是否正确，很多网站在测试完毕后并没有及时删除，因此当访问这些测试页面时，会输出服务器的关键信息，这些信息的泄露将导致服务器被渗透的风险。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Info_PHPinfo'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3183c7c0-9437-40ab-8d99-c39531cf1def'
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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload_list = ['test.php', 'phpinfo.php',
                            'php.php', 'info.php', 'test.cgi']
            for payload in payload_list:
                request = requests.get(
                    '{target}/{payload}'.format(target=self.target, payload=payload))
                if request.status_code == 200 and payload in request.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞,phpinfo敏感文件地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=request.url))
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            payload_list = ['test.php', 'phpinfo.php',
                            'php.php', 'info.php', 'test.cgi']
            for payload in payload_list:
                request = requests.get(
                    '{target}/{payload}'.format(target=self.target, payload=payload))
                if request.status_code == 200 and payload in request.text:
                    url = request.url
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞,phpinfo敏感文件地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=url))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
