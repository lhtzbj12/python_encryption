# -*- coding: utf-8 -*-
# 依赖包 pip install pycryptodome

import Crypto.Cipher as Cipher
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_cipper
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_sign
from Crypto.Hash import SHA1
import  base64

class RsaHelper(object):
    """RSA加解密签名类
    """

    def __init__(self, ciper_lib=PKCS1_v1_5_cipper, sign_lib=PKCS1_v1_5_sign, hash_lib=SHA1,
                pub_file=None, pri_file=None, pub_skey=None, pri_skey=None, pub_key=None, pri_key=None,
                reversed_size=11):

        # 加解密库
        self.ciper_lib = ciper_lib
        self.sign_lib = sign_lib
        self.hash_lib = hash_lib

        # 公钥密钥
        if pub_key:
            self.pub_key = pub_key
        elif pub_skey:
            self.pub_key = RSA.importKey(pub_skey)
        elif pub_file:
            self.pub_key = RSA.importKey(open(pub_file).read())

        if pri_key:
            self.pri_key = pri_key
        elif pri_skey:
            self.pri_key = RSA.importKey(pri_skey)
        elif pri_file:
            self.pri_key = RSA.importKey(open(pri_file).read())

        # 分块保留长度
        self.block_reversed_size = reversed_size

    # 根据key长度计算分块大小
    def get_block_size(self, rsa_key):
        try:
            # RSA仅支持限定长度内的数据的加解密，需要分块
            # 分块大小
            reserve_size = self.block_reversed_size
            key_size = rsa_key.size_in_bits()
            if (key_size % 8) != 0:
                raise RuntimeError('RSA 密钥长度非法')

            # 密钥用来解密，解密不需要预留长度
            if rsa_key.has_private():
                reserve_size = 0

            bs = int(key_size / 8) - reserve_size
        except Exception as err:
            print('计算加解密数据块大小出错', rsa_key, err)
        return bs

    # 返回块数据
    def block_data(self, data, rsa_key):
        bs = self.get_block_size(rsa_key)
        for i in range(0, len(data), bs):
            yield data[i:i + bs]

    # 加密
    def enc_bytes(self, data, key=None):
        text = b''
        try:
            rsa_key = self.pub_key
            if key:
                rsa_key = key

            cipher = self.ciper_lib.new(rsa_key)
            for dat in self.block_data(data, rsa_key):
                cur_text = cipher.encrypt(dat)
                text += cur_text
        except Exception as err:
            print('RSA加密失败', data, err)
        return text

    # 解密
    def dec_bytes(self, data, key=None):
        text = b''
        try:
            rsa_key = self.pri_key
            if key:
                rsa_key = key

            cipher = self.ciper_lib.new(rsa_key)
            for dat in self.block_data(data, rsa_key):
                if type(self.ciper_lib) == Cipher.PKCS1_v1_5:
                    cur_text = cipher.decrypt(dat)
                else:
                    cur_text = cipher.decrypt(dat, '解密异常')
                text += cur_text
        except Exception as err:
            print('RSA解密失败', data, err)
        return text

    # RSA签名
    def sign_bytes(self, data, key=None):
        signature = ''
        try:
            rsa_key = self.pri_key
            if key:
                rsa_key = key

            h = self.hash_lib.new(data)
            signature = self.sign_lib.new(rsa_key).sign(h)
        except Exception as err:
            print('RSA签名失败', '', err)
        return signature

    # RSA签名验证
    def sign_verify(self, data, sig, key=None):
        try:
            rsa_key = self.pub_key
            if key:
                rsa_key = key
            h = self.hash_lib.new(data)
            self.sign_lib.new(rsa_key).verify(h, sig)
            ret = True
        except (ValueError, TypeError):
            ret = False
        return ret

    # 读取标准的rsa公私钥pem文件
    def load_rsa_file(self,fn):
        key = None
        try:
            key = RSA.importKey(open(fn).read())
        except Exception as err:
            print('导入rsa的KEY文件出错', fn, err)
        return key


    # 标准字符串密钥转rsa格式密钥
    def rsa_key_str2std(self,skey):
        ret = None
        try:
            ret = RSA.importKey(skey)
        except Exception as err:
            print('字符串密钥转rsa格式密钥错误', skey, err)
        return ret

if __name__ == '__main__':
    pub_key = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7PyjMEuniN6BPn8oqzIZ6AO1N
jSTO9R3adCCIwKfKIEoWXXM+tHDpktdPKSaAsWJPTNAGvEvtxOfzXib/EMXKqD0e
Uy5MatfpRjRdf1hJVimmfrb09Qx2j7CsKLy7nD23m4xubdYBwvkjMwt/L3JxB5D6
qryW1wei/j1c+/OCxQIDAQAB
-----END PUBLIC KEY-----'''
    pri_key = '''-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC7PyjMEuniN6BPn8oqzIZ6AO1NjSTO9R3adCCIwKfKIEoWXXM+
tHDpktdPKSaAsWJPTNAGvEvtxOfzXib/EMXKqD0eUy5MatfpRjRdf1hJVimmfrb0
9Qx2j7CsKLy7nD23m4xubdYBwvkjMwt/L3JxB5D6qryW1wei/j1c+/OCxQIDAQAB
AoGAT7vGYJgRNf4f6qgNS4pKHTu10RcwPFyOOM7IZ9M5380+HyXuBB6MEjowKwpH
1fcy+LepwaR+5KG7b5uBGY4H2ticMtdysBd9gLwnY4Eh4j7LCWE54HvELpeWXkWp
FQdb/NQhcqMAGwYsTnRPdBqkrUmJBTYqEGkIlqCQ5vUJOCECQQDhe0KGmbq1RWp6
TDvgpA2dUmlt2fdP8oNW8O7MvbDaQRduoZnVRTPYCDKfzFqpNXL1hAYgth1N0vzD
nv3VoLcpAkEA1JcY+rLv5js1g5Luv8LaI5/3uOg0CW7fmh/LfGuz8k/OxASN+cAO
UjPHrxtc5xn1zat4/bnV5GEdlOp/DhquPQJBAIV2Fsdi4M+AueiPjPWHRQO0jvDV
jfwFOFZSn5YSRUa6NmtmPY6tumUJXSWWqKb1GwlVTuc3xBqXYsNLLUWwLhkCQQDJ
UJCiD0LohhdGEqUuSKnj5H9kxddJO4pZXFSI7UEJbJQDwcBkyn+FTm2BH+tZGZdQ
fVnlA89OJr0poOpSg+eNAkAKY85SR9KASaTiDBoPpJ8N805XEhd0Kq+ghzSThxL3
fVtKUQLiCh7Yd8oMd/G5S3xWJHUXSioATT8uPRH2bOb/
-----END RSA PRIVATE KEY-----'''

    #r = Rsa(pri_file='rsa_private_key.pem', pub_file='rsa_public_key.pem')
    r = RsaHelper(pub_skey=pub_key,pri_skey=pri_key)
    data = "hello word 中国"
    encrydata = r.enc_bytes(data.encode(encoding='utf-8'))
    encrydata =base64.b64encode(encrydata)
    print(encrydata)
    #encrydata = 'uDeQATxRbbkjTBVHXa6yi8B0KOIu7HLZuvKpXz5KNYQ8RRUTE5P3MF9d4hOG3qq+zk5z8y/1EngzFvpbsljP5qc71YQZbJEUAXARBAWB9ex7GyVlLzIA/T5bF7OmcoCr4fkWt4OYzC0aaFsKsmGDXS6aWGjD6ObulIjizDZiv8k='
    encrydata = base64.b64decode(encrydata)
    encrydata = r.dec_bytes(encrydata)
    print(encrydata.decode("utf-8"))