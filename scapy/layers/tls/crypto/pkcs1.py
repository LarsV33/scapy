## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
##                     2015, 2016 Maxence Tury
## This program is published under a GPLv2 license

"""
PKCS #1 methods as defined in RFC 3447.
"""

import os, popen2, tempfile
import math, random, struct

from scapy.config import conf, crypto_validator
if conf.crypto_valid:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
else:
    InvalidSignature = dafault_backend = hashes = padding = None

from scapy.utils import randstring, zerofree_randstring, strxor, strand
from scapy.error import warning


#####################################################################
# Some helpers
#####################################################################

# OS2IP function defined in RFC 3447 for octet string to integer conversion
def pkcs_os2ip(x):
    """
    Accepts a byte string as input parameter and return the associated long
    value:

    Input : x        octet string to be converted

    Output: x        corresponding nonnegative integer

    Reverse function is pkcs_i2osp()
    """
    return int(x.encode("hex"), 16)

# I2OSP function defined in RFC 3447 for integer to octet string conversion
def pkcs_i2osp(x, xLen):
    """
    Converts a long (the first parameter) to the associated byte string
    representation of length l (second parameter). Basically, the length
    parameters allow the function to perform the associated padding.

    Input : x        nonnegative integer to be converted
            xLen     intended length of the resulting octet string

    Output: x        corresponding octet string

    Reverse function is pkcs_os2ip().
    """
    # The user is responsible for providing an appropriate xLen.
    #if x >= 256**xLen:
    #    raise Exception("Integer too large for provided xLen %d" % xLen)
    fmt = "%%0%dx" % (2*xLen)
    return (fmt % x).decode("hex")

def pkcs_ilen(n):
    """
    This is a log base 256 which determines the minimum octet string
    length for unequivocal representation of integer n by pkcs_i2osp.
    """
    i = 0
    while n > 0:
        n >>= 8
        i += 1
    return i

# for every hash function a tuple is provided, giving access to
# - hash output length in byte
# - associated hash function that take data to be hashed as parameter
#   XXX I do not provide update() at the moment.
# - DER encoding of the leading bits of digestInfo (the hash value
#   will be concatenated to create the complete digestInfo).
#
# Notes:
# - MD4 asn.1 value should be verified. Also, as stated in
#   PKCS#1 v2.1, MD4 should not be used.
# - 'tls' one is the concatenation of both md5 and sha1 hashes used
#   by SSL/TLS when signing/verifying things

_hashFuncParams = {}
if conf.crypto_valid:

    def _hashWrapper(hash_algo, message, backend=default_backend()):
        digest = hashes.Hash(hash_algo, backend).update(message)
        return digest.finalize()

    _hashFuncParams = {
        "md5"    : (16,
                    hashes.MD5,
                    lambda x: _hashWrapper(hashes.MD5, x),
                    '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10'),
        "sha1"   : (20,
                    hashes.SHA1,
                    lambda x: _hashWrapper(hashes.SHA1, x),
                    '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'),
        "sha224" : (28,
                    hashes.SHA224,
                    lambda x: _hashWrapper(hashes.SHA224, x),
                    '\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c'),
        "sha256" : (32,
                    hashes.SHA256,
                    lambda x: _hashWrapper(hashes.SHA256, x),
                    '\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'),
        "sha384" : (48,
                    hashes.SHA384,
                    lambda x: _hashWrapper(hashes.SHA384, x),
                    '\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30'),
        "sha512" : (64,
                    hashes.SHA512,
                    lambda x: _hashWrapper(hashes.SHA512, x),
                    '\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40'),
        "tls"    : (36,
                    None,
                    lambda x: _hashWrapper(hashes.MD5, x) + _hashWrapper(hashes.SHA1, x),
                    '')
        }

def mapHashFunc(hashStr):
    try:
        return _hashFuncParams[hashStr][1]
    except:
        raise Exception("Unknown hash function %s" % hashStr)


def pkcs_mgf1(mgfSeed, maskLen, h):
    """
    Implements generic MGF1 Mask Generation function as described in
    Appendix B.2.1 of RFC 3447. The hash function is passed by name.
    valid values are 'md2', 'md4', 'md5', 'sha1', 'tls, 'sha256',
    'sha384' and 'sha512'. Returns None on error.

    Input:
       mgfSeed: seed from which mask is generated, an octet string
       maskLen: intended length in octets of the mask, at most 2^32 * hLen
                hLen (see below)
       h      : hash function name (in 'md2', 'md4', 'md5', 'sha1', 'tls',
                'sha256', 'sha384'). hLen denotes the length in octets of
                the hash function output.

    Output:
       an octet string of length maskLen
    """

    # steps are those of Appendix B.2.1
    if not _hashFuncParams.has_key(h):
        warning("pkcs_mgf1: invalid hash (%s) provided" % h)
        return None
    hLen = _hashFuncParams[h][0]
    hFunc = _hashFuncParams[h][2]
    if maskLen > 2**32 * hLen:                               # 1)
        warning("pkcs_mgf1: maskLen > 2**32 * hLen")
        return None
    T = ""                                                   # 2)
    maxCounter = math.ceil(float(maskLen) / float(hLen))     # 3)
    counter = 0
    while counter < maxCounter:
        C = pkcs_i2osp(counter, 4)
        T += hFunc(mgfSeed + C)
        counter += 1
    return T[:maskLen]


def pkcs_emsa_pss_encode(M, emBits, h, mgf, sLen):
    """
    Implements EMSA-PSS-ENCODE() function described in Sect. 9.1.1 of RFC 3447

    Input:
       M     : message to be encoded, an octet string
       emBits: maximal bit length of the integer resulting of pkcs_os2ip(EM),
               where EM is the encoded message, output of the function.
       h     : hash function name (in 'md2', 'md4', 'md5', 'sha1', 'tls',
               'sha256', 'sha384'). hLen denotes the length in octets of
               the hash function output.
       mgf   : the mask generation function f : seed, maskLen -> mask
       sLen  : intended length in octets of the salt

    Output:
       encoded message, an octet string of length emLen = ceil(emBits/8)

    On error, None is returned.
    """

    # 1) is not done
    hLen = _hashFuncParams[h][0]                             # 2)
    hFunc = _hashFuncParams[h][2]
    mHash = hFunc(M)
    emLen = int(math.ceil(emBits/8.))
    if emLen < hLen + sLen + 2:                              # 3)
        warning("encoding error (emLen < hLen + sLen + 2)")
        return None
    salt = randstring(sLen)                                  # 4)
    MPrime = '\x00'*8 + mHash + salt                         # 5)
    H = hFunc(MPrime)                                        # 6)
    PS = '\x00'*(emLen - sLen - hLen - 2)                    # 7)
    DB = PS + '\x01' + salt                                  # 8)
    dbMask = mgf(H, emLen - hLen - 1)                        # 9)
    maskedDB = strxor(DB, dbMask)                            # 10)
    l = (8*emLen - emBits)/8                                 # 11)
    rem = 8*emLen - emBits - 8*l # additionnal bits
    andMask = l*'\x00'
    if rem:
        j = chr(reduce(lambda x,y: x+y, map(lambda x: 1<<x, range(8-rem))))
        andMask += j
        l += 1
    maskedDB = strand(maskedDB[:l], andMask) + maskedDB[l:]
    EM = maskedDB + H + '\xbc'                               # 12)
    return EM                                                # 13)


def pkcs_emsa_pss_verify(M, EM, emBits, h, mgf, sLen):
    """
    Implements EMSA-PSS-VERIFY() function described in Sect. 9.1.2 of RFC 3447

    Input:
       M     : message to be encoded, an octet string
       EM    : encoded message, an octet string of length emLen=ceil(emBits/8)
       emBits: maximal bit length of the integer resulting of pkcs_os2ip(EM)
       h     : hash function name (in 'md2', 'md4', 'md5', 'sha1', 'tls',
               'sha256', 'sha384'). hLen denotes the length in octets of
               the hash function output.
       mgf   : the mask generation function f : seed, maskLen -> mask
       sLen  : intended length in octets of the salt

    Output:
       True if the verification is ok, False otherwise.
    """

    # 1) is not done
    hLen = _hashFuncParams[h][0]                             # 2)
    hFunc = _hashFuncParams[h][2]
    mHash = hFunc(M)
    emLen = int(math.ceil(emBits/8.))                        # 3)
    if emLen < hLen + sLen + 2:
        return False
    if EM[-1] != '\xbc':                                     # 4)
        return False
    l = emLen - hLen - 1                                     # 5)
    maskedDB = EM[:l]
    H = EM[l:l+hLen]
    l = (8*emLen - emBits)/8                                 # 6)
    rem = 8*emLen - emBits - 8*l # additionnal bits
    andMask = l*'\xff'
    if rem:
        val = reduce(lambda x,y: x+y, map(lambda x: 1<<x, range(8-rem)))
        j = chr(~val & 0xff)
        andMask += j
        l += 1
    if strand(maskedDB[:l], andMask) != '\x00'*l:
        return False
    dbMask = mgf(H, emLen - hLen - 1)                        # 7)
    DB = strxor(maskedDB, dbMask)                            # 8)
    l = (8*emLen - emBits)/8                                 # 9)
    rem = 8*emLen - emBits - 8*l # additionnal bits
    andMask = l*'\x00'
    if rem:
        j = chr(reduce(lambda x,y: x+y, map(lambda x: 1<<x, range(8-rem))))
        andMask += j
        l += 1
    DB = strand(DB[:l], andMask) + DB[l:]
    l = emLen - hLen - sLen - 1                              # 10)
    if DB[:l] != '\x00'*(l-1) + '\x01':
        return False
    salt = DB[-sLen:]                                        # 11)
    MPrime = '\x00'*8 + mHash + salt                         # 12)
    HPrime = hFunc(MPrime)                                   # 13)
    return H == HPrime                                       # 14)


def pkcs_emsa_pkcs1_v1_5_encode(M, emLen, h): # section 9.2 of RFC 3447
    """
    Implements EMSA-PKCS1-V1_5-ENCODE() function described in Sect.
    9.2 of RFC 3447.

    Input:
       M    : message to be encode, an octet string
       emLen: intended length in octets of the encoded message, at least
              tLen + 11, where tLen is the octet length of the DER encoding
              T of a certain value computed during the encoding operation.
       h    : hash function name (in 'md2', 'md4', 'md5', 'sha1', 'tls',
              'sha256', 'sha384'). hLen denotes the length in octets of
              the hash function output.

    Output:
       encoded message, an octet string of length emLen

    On error, None is returned.
    """
    hLen = _hashFuncParams[h][0]                             # 1)
    hFunc = _hashFuncParams[h][2]
    H = hFunc(M)
    hLeadingDigestInfo = _hashFuncParams[h][3]               # 2)
    T = hLeadingDigestInfo + H
    tLen = len(T)
    if emLen < tLen + 11:                                    # 3)
        warning("pkcs_emsa_pkcs1_v1_5_encode:"
                "intended encoded message length too short")
        return None
    PS = '\xff'*(emLen - tLen - 3)                           # 4)
    EM = '\x00' + '\x01' + PS + '\x00' + T                   # 5)
    return EM                                                # 6)


# XXX should add other pgf1 instance in a better fashion.

def create_ca_file(anchor_list, filename):
    """
    Concatenate all the certificates (PEM format for the export) in
    'anchor_list' and write the result to file 'filename'. On success
    'filename' is returned, None otherwise.

    If you are used to OpenSSL tools, this function builds a CAfile
    that can be used for certificate and CRL check.

    Also see create_temporary_ca_file().
    """
    try:
        f = open(filename, "w")
        for a in anchor_list:
            s = a.output(fmt="PEM")
            f.write(s)
        f.close()
    except:
        return None
    return filename

def create_temporary_ca_file(anchor_list):
    """
    Concatenate all the certificates (PEM format for the export) in
    'anchor_list' and write the result to file to a temporary file
    using mkstemp() from tempfile module. On success 'filename' is
    returned, None otherwise.

    If you are used to OpenSSL tools, this function builds a CAfile
    that can be used for certificate and CRL check.
    """
    try:
        f, fname = tempfile.mkstemp()
        for a in anchor_list:
            s = a.output(fmt="PEM")
            l = os.write(f, s)
        os.close(f)
    except:
        return None
    return fname

def create_temporary_ca_path(anchor_list, folder):
    """
    Create a CA path folder as defined in OpenSSL terminology, by
    storing all certificates in 'anchor_list' list in PEM format
    under provided 'folder' and then creating the associated links
    using the hash as usually done by c_rehash.

    Note that you can also include CRL in 'anchor_list'. In that
    case, they will also be stored under 'folder' and associated
    links will be created.

    In folder, the files are created with names of the form
    0...ZZ.pem. If you provide an empty list, folder will be created
    if it does not already exist, but that's all.

    The number of certificates written to folder is returned on
    success, None on error.
    """
    # We should probably avoid writing duplicate anchors and also
    # check if they are all certs.
    try:
        if not os.path.isdir(folder):
            os.makedirs(folder)
    except:
        return None

    l = len(anchor_list)
    if l == 0:
        return None
    fmtstr = "%%0%sd.pem" % math.ceil(math.log(l, 10))
    i = 0
    try:
        for a in anchor_list:
            fname = os.path.join(folder, fmtstr % i)
            f = open(fname, "w")
            s = a.output(fmt="PEM")
            f.write(s)
            f.close()
            i += 1
    except:
        return None

    r,w=popen2.popen2("c_rehash %s" % folder)
    r.close(); w.close()

    return l


#####################################################################
# Public Key Cryptography related stuff
#####################################################################

class _EncryptAndVerifyRSA(object):
    @crypto_validator
    def encrypt(self, m, t=None, h=None, mgf=None, L=None):
        """
        Encrypt message 'm' using 't' encryption scheme where 't' can be:

        - None: the message 'm' is directly applied the RSAEP encryption
                primitive, as described in PKCS#1 v2.1, i.e. RFC 3447
                Sect 5.1.1. Simply put, the message undergo a modular
                exponentiation using the public key. Additionnal method
                parameters are just ignored.

        -'pkcs': the message 'm' is applied RSAES-PKCS1-V1_5-ENCRYPT encryption
                scheme as described in section 7.2.1 of RFC 3447. In that
                context, other parameters ('h', 'mgf', 'l') are not used.

        -'oaep': the message 'm' is applied the RSAES-OAEP-ENCRYPT encryption
                scheme, as described in PKCS#1 v2.1, i.e. RFC 3447 Sect
                7.1.1. In that context,

                o 'h' parameter provides the name of the hash method to use.
                  Possible values are "md2", "md4", "md5", "sha1", "tls",
                  "sha224", "sha256", "sha384" and "sha512". If none is
                  provided, sha1 is used.

                o 'mgf' is the mask generation function. By default, mgf
                  is derived from the provided hash function using the
                  generic MGF1 (see pkcs_mgf1() for details).

                o 'L' is the optional label to be associated with the message.
                  If not provided, the default value is used, i.e the empty
                  string. No check is done on the input limitation of the hash
                  function regarding the size of 'L' (for instance, 2^61 - 1
                  for SHA-1). You have been warned.
        """
        if h is not None:
            h = mapHashFunc(h)
        if t is None: # Raw encryption
            return self.key.encrypt(
                m,
                padding.AsymmetricPadding(),
            )
        elif t == "pkcs":
            return self.key.encrypt(
                m,
                padding.PKCS1v15(),
            )

        elif t == "oaep":
            return self.key.encrypt(
                m,
                padding.OAEP(
                    mgf=mgf(h()),
                    algorithm=h(),
                    label=L,
                ),
            )

        else:
            warning("Key.encrypt(): Unknown encryption type (%s) provided" % t)
            return None

    @crypto_validator
    def verify(self, M, S, t=None, h=None, mgf=None, sLen=None):
        """
        Verify alleged signature 'S' is indeed the signature of message 'M'
        using 't' signature scheme where 't' can be:

        - None: the alleged signature 'S' is directly applied the RSAVP1
                signature primitive, as described in PKCS#1 v2.1, i.e. RFC 3447
                Sect 5.2.1. Simply put, the provided signature is applied a
                modular exponentiation using the public key. Then, a comparison
                of the result is done against 'M'. On match, True is returned.
                Additional method parameters are just ignored.

        -'pkcs': the alleged signature 'S' and message 'M' are applied
                RSASSA-PKCS1-v1_5-VERIFY signature verification scheme as
                described in Sect. 8.2.2 of RFC 3447. In that context, the hash
                function name is passed using 'h'. Possible values are "md2",
                "md4", "md5", "sha1", "tls", "sha224", "sha256", "sha384" and
                "sha512". If none is provided, sha1 is used. Other additional
                parameters are ignored.

        -'pss': the alleged signature 'S' and message 'M' are applied
                RSASSA-PSS-VERIFY signature scheme as described in Sect. 8.1.2.
                of RFC 3447. In that context,

                o 'h' parameter provides the name of the hash method to use.
                   Possible values are "md2", "md4", "md5", "sha1", "tls",
                   "sha224", "sha256", "sha384" and "sha512". If None is
                   provided, sha1 is used.

                o 'mgf' is the mask generation function. By default, mgf
                   is derived from the provided hash function using the
                   generic MGF1 (see pkcs_mgf1() for details).

                o 'sLen' is the byte length of the salt. You can overload the
                  default value (the byte length of the hash value for provided
                  algorithm) by providing another one with that parameter.
        """
        if h is not None:
            h = mapHashFunc(h)

        if t is None: # RSAVP1
            pad_inst = padding.AsymmetricPadding()
        elif t == "pkcs": # RSASSA-PKCS1-v1_5-VERIFY
            if h is None:
                h = hashes.SHA1
            pad_inst = padding.PKCS1v15()
        elif t == "pss": # RSASSA-PSS-VERIFY
            pad_inst = padding.PSS(mgf=mgf, salt_length=sLen)

        else:
            warning("Key.verify(): Unknown signature type (%s) provided" % t)
            return None

        try:
            self.key.verify(
                signature=S,
                data=M,
                padding=pad_inst,
                algorithm=h(),
            )
            return True
        except InvalidSignature:
            return False

class _DecryptAndSignRSA(object):
    ### Below are decryption related methods. Encryption ones are inherited
    ### from PubKey

    def _rsadp(self, c):
        """
        Internal method providing raw RSA decryption, i.e. simple modular
        exponentiation of the given ciphertext representative 'c', a long
        between 0 and n-1.

        This is the decryption primitive RSADP described in PKCS#1 v2.1,
        i.e. RFC 3447 Sect. 5.1.2.

        Input:
           c: ciphertest representative, a long between 0 and n-1, where
              n is the key modulus.

        Output:
           message representative, a long between 0 and n-1

        Not intended to be used directly. Please, see decrypt() method.
        """

        n = self.modulus
        if isinstance(c, int):
            c = long(c)
        if (not isinstance(c, long)) or c > n-1:
            warning("Key._rsadp() expects a long between 0 and n-1")
            return None

        return self.key.decrypt(c)


    def _rsaes_pkcs1_v1_5_decrypt(self, C):
        """
        Implements RSAES-PKCS1-V1_5-DECRYPT() function described in section
        7.2.2 of RFC 3447.

        Input:
           C: ciphertext to be decrypted, an octet string of length k, where
              k is the length in octets of the RSA modulus n.

        Output:
           an octet string of length k at most k - 11

        on error, None is returned.
        """

        # 1) Length checking
        cLen = len(C)
        k = self.modulusLen / 8
        if cLen != k or k < 11:
            warning("Key._rsaes_pkcs1_v1_5_decrypt() decryption error "
                    "(cLen != k or k < 11)")
            return None

        # 2) RSA decryption
        c = pkcs_os2ip(C)                           # 2.a)
        m = self._rsadp(c)                          # 2.b)
        EM = pkcs_i2osp(m, k)                       # 2.c)

        # 3) EME-PKCS1-v1_5 decoding

        # I am aware of the note at the end of 7.2.2 regarding error
        # conditions reporting but the one provided below are for _local_
        # debugging purposes. --arno

        if EM[0] != '\x00':
            warning("Key._rsaes_pkcs1_v1_5_decrypt(): decryption error "
                    "(first byte is not 0x00)")
            return None

        if EM[1] != '\x02':
            warning("Key._rsaes_pkcs1_v1_5_decrypt(): decryption error "
                    "(second byte is not 0x02)")
            return None

        tmp = EM[2:].split('\x00', 1)
        if len(tmp) != 2:
            warning("Key._rsaes_pkcs1_v1_5_decrypt(): decryption error "
                    "(no 0x00 to separate PS from M)")
            return None

        PS, M = tmp
        if len(PS) < 8:
            warning("Key._rsaes_pkcs1_v1_5_decrypt(): decryption error "
                    "(PS is less than 8 byte long)")
            return None

        return M                                    # 4)


    def _rsaes_oaep_decrypt(self, C, h=None, mgf=None, L=None):
        """
        Internal method providing RSAES-OAEP-DECRYPT as defined in Sect.
        7.1.2 of RFC 3447. Not intended to be used directly. Please, see
        encrypt() method for type "OAEP".


        Input:
           C  : ciphertext to be decrypted, an octet string of length k, where
                k = 2*hLen + 2 (k denotes the byte length of the RSA modulus
                and hLen the byte length of the hash function output)
           h  : hash function name (in 'md2', 'md4', 'md5', 'sha1', 'tls',
                'sha256', 'sha384'). 'sha1' is used if none is provided.
           mgf: the mask generation function f : seed, maskLen -> mask
           L  : optional label whose association with the message is to be
                verified; the default value for L, if not provided is the empty
                string.

        Output:
           message, an octet string of length k mLen, where mLen <= k-2*hLen-2

        On error, None is returned.
        """
        # The steps below are the one described in Sect. 7.1.2 of RFC 3447.

        # 1) Length Checking
                                                    # 1.a) is not done
        if h is None:
            h = "sha1"
        if not _hashFuncParams.has_key(h):
            warning("Key._rsaes_oaep_decrypt(): unknown hash function %s." % h)
            return None
        hLen = _hashFuncParams[h][0]
        hFun = _hashFuncParams[h][2]
        k = self.modulusLen / 8
        cLen = len(C)
        if cLen != k:                               # 1.b)
            warning("Key._rsaes_oaep_decrypt(): decryption error. "
                    "(cLen != k)")
            return None
        if k < 2*hLen + 2:
            warning("Key._rsaes_oaep_decrypt(): decryption error. "
                    "(k < 2*hLen + 2)")
            return None

        # 2) RSA decryption
        c = pkcs_os2ip(C)                           # 2.a)
        m = self._rsadp(c)                          # 2.b)
        EM = pkcs_i2osp(m, k)                       # 2.c)

        # 3) EME-OAEP decoding
        if L is None:                               # 3.a)
            L = ""
        lHash = hFun(L)
        Y = EM[:1]                                  # 3.b)
        if Y != '\x00':
            warning("Key._rsaes_oaep_decrypt(): decryption error. "
                    "(Y is not zero)")
            return None
        maskedSeed = EM[1:1+hLen]
        maskedDB = EM[1+hLen:]
        if mgf is None:
            mgf = lambda x,y: pkcs_mgf1(x, y, h)
        seedMask = mgf(maskedDB, hLen)              # 3.c)
        seed = strxor(maskedSeed, seedMask)         # 3.d)
        dbMask = mgf(seed, k - hLen - 1)            # 3.e)
        DB = strxor(maskedDB, dbMask)               # 3.f)

        # I am aware of the note at the end of 7.1.2 regarding error
        # conditions reporting but the one provided below are for _local_
        # debugging purposes. --arno

        lHashPrime = DB[:hLen]                      # 3.g)
        tmp = DB[hLen:].split('\x01', 1)
        if len(tmp) != 2:
            warning("Key._rsaes_oaep_decrypt(): decryption error. "
                    "(0x01 separator not found)")
            return None
        PS, M = tmp
        if PS != '\x00'*len(PS):
            warning("Key._rsaes_oaep_decrypt(): decryption error. "
                    "(invalid padding string)")
            return None
        if lHash != lHashPrime:
            warning("Key._rsaes_oaep_decrypt(): decryption error. "
                    "(invalid hash)")
            return None
        return M                                    # 4)


    def decrypt(self, C, t=None, h=None, mgf=None, L=None):
        """
        Decrypt ciphertext 'C' using 't' decryption scheme where 't' can be:

        - None: the ciphertext 'C' is directly applied the RSADP decryption
                primitive, as described in PKCS#1 v2.1, i.e. RFC 3447
                Sect 5.1.2. Simply, put the message undergo a modular
                exponentiation using the private key. Additionnal method
                parameters are just ignored.

        - 'pkcs': the ciphertext 'C' is applied RSAES-PKCS1-V1_5-DECRYPT
                decryption scheme as described in section 7.2.2 of RFC 3447.
                In that context, other parameters ('h', 'mgf', 'l') are not
                used.

        - 'oaep': the ciphertext 'C' is applied the RSAES-OAEP-DECRYPT
                decryption scheme, as described in PKCS#1 v2.1, i.e. RFC 3447
                Sect 7.1.2. In that context,

                o 'h' parameter provides the name of the hash method to use.
                  Possible values are "md2", "md4", "md5", "sha1", "tls",
                  "sha224", "sha256", "sha384" and "sha512". If None is
                  provided, sha1 is used by default.

                o 'mgf' is the mask generation function. By default, mgf
                  is derived from the provided hash function using the
                  generic MGF1 (see pkcs_mgf1() for details).

                o 'L' is the optional label to be associated with the
                  message. If not provided, the default value is used, i.e
                  the empty string. No check is done on the input limitation
                  of the hash function regarding the size of 'L' (for
                  instance, 2^61 - 1 for SHA-1). You have been warned.
        """
        if t is None:
            C = pkcs_os2ip(C)
            c = self._rsadp(C)
            l = int(math.ceil(math.log(c, 2) / 8.)) # Hack
            return pkcs_i2osp(c, l)

        elif t == "pkcs":
            return self._rsaes_pkcs1_v1_5_decrypt(C)

        elif t == "oaep":
            return self._rsaes_oaep_decrypt(C, h, mgf, L)

        else:
            warning("Key.decrypt(): Unknown decryption type (%s) provided" % t)
            return None

    ### Below are signature related methods.
    ### Verification methods are inherited from PubKey.

    def _rsasp1(self, m):
        """
        Internal method providing raw RSA signature, i.e. simple modular
        exponentiation of the given message representative 'm', an integer
        between 0 and n-1.

        This is the signature primitive RSASP1 described in PKCS#1 v2.1,
        i.e. RFC 3447 Sect. 5.2.1.

        Input:
           m: message representative, an integer between 0 and n-1, where
              n is the key modulus.

        Output:
           signature representative, an integer between 0 and n-1

        Not intended to be used directly. Please, see sign() method.
        """
        return self._rsadp(m)


    def _rsassa_pss_sign(self, M, h=None, mgf=None, sLen=None):
        """
        Implements RSASSA-PSS-SIGN() function described in Sect. 8.1.1 of
        RFC 3447.

        Input:
           M: message to be signed, an octet string

        Output:
           signature, an octet string of length k, where k is the length in
           octets of the RSA modulus n.

        On error, None is returned.
        """

        # Set default parameters if not provided
        if h is None: # By default, sha1
            h = "sha1"
        if not _hashFuncParams.has_key(h):
            warning("Key._rsassa_pss_sign(): unknown hash function "
                    "provided (%s)" % h)
            return None
        if mgf is None: # use mgf1 with underlying hash function
            mgf = lambda x,y: pkcs_mgf1(x, y, h)
        if sLen is None: # use Hash output length (A.2.3 of RFC 3447)
            hLen = _hashFuncParams[h][0]
            sLen = hLen

        # 1) EMSA-PSS encoding
        modBits = self.modulusLen
        k = modBits / 8
        EM = pkcs_emsa_pss_encode(M, modBits - 1, h, mgf, sLen)
        if EM is None:
            warning("Key._rsassa_pss_sign(): unable to encode")
            return None

        # 2) RSA signature
        m = pkcs_os2ip(EM)                          # 2.a)
        s = self._rsasp1(m)                         # 2.b)
        S = pkcs_i2osp(s, k)                        # 2.c)

        return S                                    # 3)


    def _rsassa_pkcs1_v1_5_sign(self, M, h):
        """
        Implements RSASSA-PKCS1-v1_5-SIGN() function as described in
        Sect. 8.2.1 of RFC 3447.

        Input:
           M: message to be signed, an octet string
           h: hash function name (in 'md2', 'md4', 'md5', 'sha1', 'tls'
                'sha256', 'sha384').

        Output:
           the signature, an octet string.
        """

        # 1) EMSA-PKCS1-v1_5 encoding
        k = self.modulusLen / 8
        EM = pkcs_emsa_pkcs1_v1_5_encode(M, k, h)
        if EM is None:
            warning("Key._rsassa_pkcs1_v1_5_sign(): unable to encode")
            return None

        # 2) RSA signature
        m = pkcs_os2ip(EM)                          # 2.a)
        s = self._rsasp1(m)                         # 2.b)
        S = pkcs_i2osp(s, k)                        # 2.c)

        return S                                    # 3)


    def sign(self, M, t=None, h=None, mgf=None, sLen=None):
        """
        Sign message 'M' using 't' signature scheme where 't' can be:

        - None: the message 'M' is directly applied the RSASP1 signature
                primitive, as described in PKCS#1 v2.1, i.e. RFC 3447 Sect
                5.2.1. Simply put, the message undergo a modular exponentiation
                using the private key. Additional method parameters are just
                ignored.

        - 'pkcs': the message 'M' is applied RSASSA-PKCS1-v1_5-SIGN signature
                scheme as described in Sect. 8.2.1 of RFC 3447. In that
                context, the hash function name is passed using 'h'. Possible
                values are "md2", "md4", "md5", "sha1", "tls", "sha224",
                "sha256", "sha384" and "sha512". If none is provided, sha1 is
                used. Other additional parameters are ignored.

        - 'pss' : the message 'M' is applied RSASSA-PSS-SIGN signature scheme
                as described in Sect. 8.1.1. of RFC 3447. In that context,

                o 'h' parameter provides the name of the hash method to use.
                   Possible values are "md2", "md4", "md5", "sha1", "tls",
                   "sha224", "sha256", "sha384" and "sha512". If None is
                   provided, sha1 is used.

                o 'mgf' is the mask generation function. By default, mgf
                   is derived from the provided hash function using the
                   generic MGF1 (see pkcs_mgf1() for details).

                o 'sLen' is the byte length of the salt. You can overload the
                  default value (the byte length of the hash value for provided
                  algorithm) by providing another one with that parameter.
        """

        if t is None: # RSASP1
            M = pkcs_os2ip(M)
            n = self.modulus
            if M > n-1:
                warning("Message to be signed is too long for key modulus")
                return None
            s = self._rsasp1(M)
            if s is None:
                return None
            return pkcs_i2osp(s, self.modulusLen/8)

        elif t == "pkcs": # RSASSA-PKCS1-v1_5-SIGN
            if h is None:
                h = "sha1"
            return self._rsassa_pkcs1_v1_5_sign(M, h)

        elif t == "pss": # RSASSA-PSS-SIGN
            return self._rsassa_pss_sign(M, h, mgf, sLen)

        else:
            warning("Key.sign(): Unknown signature type (%s) provided" % t)
            return None


