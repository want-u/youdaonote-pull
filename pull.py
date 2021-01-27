#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import sys
import time
import hashlib
import os
import json
import shutil
import logging

# logging.basicConfig(level=logging.INFO)

__author__ = 'Depp Wang (deppwxq@gmail.com)'
__github__ = 'https//github.com/DeppWang/youdaonote-pull'


def timestamp() -> str:
    return str(int(time.time() * 1000))


def check_config(config_name) -> dict:
    """ 检查 config.json 文件格式 """

    with open(config_name, 'rb') as f:
        config_str = f.read().decode('utf-8')
        # logging.info('config_str 格式：\n %s', config_str)

    try:
        # 将字符串转换为字典
        config_dict = eval(config_str)
    except SyntaxError:
        raise SyntaxError('请检查「config.json」格式是否为 utf-8 的 json！建议使用 Sublime 编辑「config.json」')

    # 如果某个 key 不存在，抛出异常
    try:
        config_dict['username']
        config_dict['password']
        config_dict['local_dir']
        config_dict['ydnote_dir']
    except KeyError:
        raise KeyError('请检查「config.json」的 key 是否分别为 username, password, local_dir, ydnote_dir')

    if config_dict['username'] == '' or config_dict['password'] == '':
        raise ValueError('账号密码不能为空，请检查「config.json」！')

    return config_dict


def covert_cookies(file_name) -> list:
    if not os.path.exists(file_name):
        logging.info('%s is null', file_name)
        raise OSError(file_name + ' 不存在')

    with open(file_name, 'r', encoding='utf-8') as f:
        json_str = f.read()

    try:
        # 将字符串转换为字典
        cookies_dict = eval(json_str)
        cookies = cookies_dict['cookies']
    except Exception:
        raise Exception('转换「' + file_name + '」为字典时出现错误')
    return cookies


class LoginError(ValueError):
    pass


class YoudaoNoteSession(requests.Session):
    """ 继承于 requests.Session，能像浏览器一样，完成一个完整的 Session 操作"""

    # 类变量，不随着对象改变
    WEB_URL = 'https://note.youdao.com/web/'
    SIGN_IN_URL = 'https://note.youdao.com/signIn/index.html?&callback=https%3A%2F%2Fnote.youdao.com%2Fweb%2F&from=web'  # 浏览器在传输链接的过程中是否都将符号转换为 Unicode？
    LOGIN_URL = 'https://note.youdao.com/login/acc/urs/verify/check?app=web&product=YNOTE&tp=urstoken&cf=6&fr=1&systemName=&deviceType=&ru=https%3A%2F%2Fnote.youdao.com%2FsignIn%2F%2FloginCallback.html&er=https%3A%2F%2Fnote.youdao.com%2FsignIn%2F%2FloginCallback.html&vcode=&systemName=&deviceType=&timestamp='
    COOKIE_URL = 'https://note.youdao.com/yws/mapi/user?method=get&multilevelEnable=true&_=%s'
    ROOT_ID_URL = 'https://note.youdao.com/yws/api/personal/file?method=getByPath&keyfrom=web&cstk=%s'
    DIR_MES_URL = 'https://note.youdao.com/yws/api/personal/file/%s?all=true&f=true&len=200&sort=1&isReverse=false&method=listPageByParentId&keyfrom=web&cstk=%s'
    FILE_URL = 'https://note.youdao.com/yws/api/personal/sync?method=download&keyfrom=web&cstk=%s'

    # 莫有类方法

    def __init__(self):

        # 使用父类的构造函数初始化 self
        requests.Session.__init__(self)

        self.headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        }

        # 属于对象变量
        self.cstk = None
        self.local_dir = None

    def check_and_login(self, username, password) -> str:
        try:
            cookies = covert_cookies('cookies.json')
        except Exception as err:
            logging.info('covert_cookies error: %s', format(err))
            cookies = None

        # 如果 cookies 不为 null，使用 cookies 登录
        if cookies is not None:
            # 如果 Cookies 被修改或过期等原因导致 Cookies 登录失败，改用使用账号密码登录
            try:
                root_id = self.cookies_login(cookies)
                print('本次使用 Cookies 登录')
            except KeyError as err:
                logging.info('cookie 登录出错：%s', format(err))
                root_id = self.login(username, password)
                print('本次使用账号密码登录，已将 Cookies 保存到「cookies.json」中，下次使用 Cookies 登录')
        else:
            root_id = self.login(username, password)
            print('本次使用账号密码登录，已将 Cookies 保存到「cookies.json」中，下次使用 Cookies 登录')

        return root_id

    def login(self, username, password) -> str:
        """ 模拟浏览器用户操作，使用账号密码登录，并保存 Cookie """

        # 模拟打开网页版
        self.get(self.WEB_URL)
        # 模拟设置上一步链接
        self.headers['Referer'] = self.WEB_URL
        # 模拟重定向跳转到登录页
        self.get(self.SIGN_IN_URL)
        # 模拟设置上一步链接
        self.headers['Referer'] = self.SIGN_IN_URL
        # 模拟跳转到登录页后的请求连接
        self.get('https://note.youdao.com/login/acc/pe/getsess?product=YNOTE&_=%s' % timestamp())
        self.get('https://note.youdao.com/auth/cq.json?app=web&_=%s' % timestamp())
        self.get('https://note.youdao.com/auth/urs/login.json?app=web&_=%s' % timestamp())

        data = {
            'username': username,
            'password': hashlib.md5(password.encode('utf-8')).hexdigest()
        }

        logging.info('cookies: %s', self.cookies)

        # 模拟登陆
        self.post(self.LOGIN_URL,
                  data=data, allow_redirects=True)

        # 登录成功后的链接，里面包含可用于登录的最新 Cookie: YNOTE_CSTK
        self.get(self.COOKIE_URL % timestamp())

        logging.info('new cookies: %s', self.cookies)

        # 设置 cookies
        cstk = self.cookies.get('YNOTE_CSTK')

        if cstk is None:
            logging.info('cstk: %s', cstk)
            raise LoginError('请检查账号密码是否正确！也可能因操作频繁导致需要验证码，请切换网络（改变 ip）或等待一段时间后重试！')

        self.cstk = cstk

        self.save_cookies()

        return self.get_root_id()

    def save_cookies(self) -> None:
        """ 将 Cookies 保存到 cookies.json """

        cookies_dict = {}
        cookies = []

        # cookiejar 为 RequestsCookieJar，相当于是一个 Map 对象
        cookiejar = self.cookies
        for cookie in cookiejar:
            cookie_eles = [cookie.name, cookie.value, cookie.domain, cookie.path]
            cookies.append(cookie_eles)

        cookies_dict['cookies'] = cookies

        with open('cookies.json', 'wb') as f:
            f.write(str(json.dumps(cookies_dict, indent=4, sort_keys=True)).encode())

    def cookies_login(self, cookies_dict) -> str:
        """ 使用 Cookies 登录，其实就是设置 Cookies """

        cookiejar = self.cookies
        for cookie in cookies_dict:
            cookiejar.set(cookie[0], cookie[1], domain=cookie[2], path=cookie[3])

        self.cstk = cookies_dict[0][1]

        return self.get_root_id()

    def get_root_id(self) -> str:
        """
        获取有道云笔记 root_id
        root_id 始终不会改变？可保存？可能会改变，几率很小。可以保存，保存又会带来新的复杂度。只要登录后，获取一下也没有影响
        """

        data = {
            'path': '/',
            'entire': 'true',
            'purge': 'false',
            'cstk': self.cstk
        }
        response = self.post(self.ROOT_ID_URL % self.cstk, data=data)
        json_obj = json.loads(response.content)
        try:
            return json_obj['fileEntry']['id']
        # Cookie 登录时可能错误
        except KeyError:
            raise KeyError('Cookie 中没有 cstk')
            # parsed = json.loads(response.content.decode('utf-8'))
            # raise LoginError('请检查账号密码是否正确！也可能因操作频繁导致需要验证码，请切换网络（改变 ip）或等待一段时间后重试！接口返回内容：',
            #                  json.dumps(parsed, indent=4, sort_keys=True))

    def get_all(self, local_dir, ydnote_dir, root_id) -> None:
        """ 下载所有文件 """

        # 如果本地为指定文件夹，下载到当前路径的 youdaonote 文件夹中，如果是 Windows 系统，将路径分隔符（\\）替换为 /
        if local_dir == '':
            local_dir = os.path.join(os.getcwd(), 'youdaonote', ydnote_dir).replace('\\', '/')

        # 如果指定的本地文件夹不存在，创建文件夹
        if not os.path.exists(local_dir):
            try:
                os.makedirs(local_dir, exist_ok=True)
            except FileNotFoundError:
                raise FileNotFoundError('请检查「%s」上层文件夹是否存在，并使用绝对路径！' % local_dir)

        # 有道云笔记指定导出文件夹名不为 '' 时，获取文件夹 id
        if ydnote_dir != '':
            root_id = self.get_dir_id(root_id, ydnote_dir)
            logging.info('root_id: %s', root_id)
            if root_id is None:
                raise ValueError('此文件夹「%s」不是顶层文件夹，暂不能下载！' % ydnote_dir)

        self.local_dir = local_dir  # 此处设置，后面会用，避免传参
        self.get_file_recursively(root_id, local_dir, ydnote_dir)

    def get_dir_id(self, root_id, ydnote_dir) -> str:
        """ 获取有道云笔记指定文件夹 id，目前指定文件夹只能为顶层文件夹，如果要指定文件夹下面的文件夹，请自己改用递归实现 """

        url = self.DIR_MES_URL % (root_id, self.cstk)
        response = self.get(url)
        json_obj = json.loads(response.content)
        try:
            entries = json_obj['entries']
        except KeyError:
            raise KeyError('有道云笔记修改了接口地址，此脚本暂时不能使用！请提 issue')

        for entry in entries:
            file_entry = entry['fileEntry']
            name = file_entry['name']
            if name == ydnote_dir:
                return file_entry['id']

    def get_file_recursively(self, id, local_dir, ydnote_dir) -> None:
        """ 递归遍历，根据 id 找到目录下的所有文件 """

        url = self.DIR_MES_URL % (id, self.cstk)

        response = self.get(url)
        json_obj = json.loads(response.content)

        try:
            json_obj['count']
        # 如果 json_obj 不是 json，退出
        except KeyError:
            logging.info('json_obj: %s', json_obj)
            raise KeyError('有道云笔记修改了接口地址，此脚本暂时不能使用！请提 issue')

        for entry in json_obj['entries']:
            file_entry = entry['fileEntry']
            name = file_entry['name']
            id = file_entry['id']
            file_path = os.path.join(local_dir, name)

            # 如果是目录，继续遍历目录下文件
            if file_entry['dir']:
                sub_dir = os.path.join(local_dir, name)
                os.makedirs(sub_dir, exist_ok=True)

                self.get_file_recursively(id, sub_dir, ydnote_dir)
            if name.endswith('.md'):
                logging.info('name: %s', file_path)
                item[name] = file_path


# 将本地同步的md文件，拷贝到youdaoyunnote
def cp_md_git():
    # 有道云本地文件目录
    local_md = check_config('config.json').get('local_md')
    dst_files = os.walk(local_md)
    for each in dst_files:
        for each_file in each[2]:
            if each_file.endswith('.md'):
                full_name = f'{each[0]}/{each_file}'
                file_name = os.path.basename(full_name)
                if file_name in item:
                    print(full_name)
                    if os.path.exists(item[file_name]):
                        print('file is exists: ', file_name)
                    else:
                        # 保存到youdaoyunnote目录下
                        shutil.copy2(full_name, item[file_name])
                        print('copy ok: ', file_name)


def main():
    start_time = int(time.time())

    try:
        config_dict = check_config('config.json')
        session = YoudaoNoteSession()
        root_id = session.check_and_login(config_dict['username'], config_dict['password'])
        print('正在 pull，请稍后 ...')
        for each in config_dict['ydnote_dir']:
            print(each)
            session.get_all(config_dict['local_dir'], each, root_id)

    except requests.exceptions.ProxyError as proxyErr:
        print('请检查网络代理设置；也有可能是调用有道云笔记接口次数达到限制，请等待一段时间后重新运行脚本，若一直失败，可删除「cookies.json」后重试')
        print('错误提示：' + format(proxyErr))
        print('已终止执行')
        sys.exit(1)
    except requests.exceptions.ConnectionError as connectionErr:
        print('网络错误，请检查网络是否正常连接。若突然执行中断，可忽略此错误，重新运行脚本')
        print('错误提示：' + format(connectionErr))
        print('已终止执行')
        sys.exit(1)
    except LoginError as loginErr:
        print('错误提示：' + format(loginErr))
        print('已终止执行')
        sys.exit(1)
    # 链接错误等异常
    except Exception as err:
        print('错误提示：' + format(err))
        print('已终止执行')
        sys.exit(1)

    end_time = int(time.time())
    print('运行完成！耗时 %s 秒' % str(end_time - start_time))


if __name__ == '__main__':
    item = {}
    main()
    cp_md_git()
