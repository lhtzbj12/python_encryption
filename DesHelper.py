import base64
import pyDes


class DesHelper(object):
    '''
      Des对称加密工具类
    :param data:
    :param app_key:
    :return:
    '''

    def encrypt(self, data, key, iv):
        '''
        Des对称加密
        :param data: 需要加密的内容
        :param key:  加密key 8 位
        :param iv:   偏移向量 8位
        :return:
        '''
        k = pyDes.des(key, pyDes.CBC, iv, pad=None, padmode=pyDes.PAD_PKCS5)
        d = k.encrypt(data)
        d = base64.b64encode(d)
        return d

    def decrypt(self, encData, key, iv):
        '''
        Des对称解密
        :param encData: 加密后的密文
        :param key:     解密key 8位
        :param iv:      偏移向量 8位
        :return:
        '''
        k = pyDes.des(key, pyDes.CBC, iv, pad=None, padmode=pyDes.PAD_PKCS5)
        data = base64.b64decode(encData)
        d = k.decrypt(data)
        return d

    def tripleEncrypt(self, data, key, iv):
        '''
        3D Des对称加密
        :param data: 需要加密的内容
        :param key:  加密key 24位
        :param iv:   偏移向量 8位
        :return:
        '''
        k = pyDes.triple_des(key, pyDes.CBC, iv, pad=None, padmode=pyDes.PAD_PKCS5)
        d = k.encrypt(data)
        d = base64.b64encode(d)
        return d

    def tripleDecrypt(self, encData, key, iv):
        '''
        3D Des对称解密
        :param encData: 加密后的密文
        :param key:     解密key 24位
        :param iv:      偏移向量 8位
        :return:
        '''
        k = pyDes.triple_des(key, pyDes.CBC, iv, pad=None, padmode=pyDes.PAD_PKCS5)
        data = base64.b64decode(encData)
        d = k.decrypt(data)
        return d

if __name__ == '__main__':
    h = DesHelper()
    # 加解密key
    key = 'ajglslslajglslslajglslsl'
    iv = 'kie8dkjd'
    # 原文
    data = 'abcdsdfasdfawe3234234234'
    print('原文：',data)
    print('******** 分隔线 **********')
    # 对称加密密文
    encData = h.encrypt(data,key[0:8],iv)
    print('密文：',encData)
    # 对称解密结果
    decData = h.decrypt(encData,key[0:8],iv)
    print('解密：',decData)
    print('******** 分隔线 **********')
    encData = h.tripleEncrypt(data, key, iv)
    print('密文：', encData)
    # 对称解密结果
    decData = h.tripleDecrypt(encData, key, iv)
    print('解密：', decData)