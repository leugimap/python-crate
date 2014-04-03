from Crypto.Cipher import DES
from Crypto.Hash import MD5
from os import urandom

class PBEWithMD5AndDES():
  def __init__(self, password, count=1000):
    self._blocksize = 8
    self._pwd = password
    self._iterations = count


  def _setPKCSKeys(self, salt):
    h = MD5.new(self._pwd)
    h.update(salt)
    for i in xrange(1, self._iterations):
      h = MD5.new(h.digest())

    dk = h.digest()
    self._kv = dk[0:8]
    self._iv = dk[8:]
    

  def encrypt(self, text):
    salt = urandom(self._blocksize)
    self._setPKCSKeys(salt)
    padding = self._blocksize - len(text) % self._blocksize
    extended_message = text + padding * chr(padding)
    cipher = DES.new(self._kv, DES.MODE_CBC, self._iv)

    res = salt + cipher.encrypt(extended_message)

    return res.encode('base64')[:-1]


  def encryptENC(self, text):
    return 'ENC(%s)' % self.encrypt(text)


  def decrypt(self, message):
    if message.startswith('ENC(') and message.endswith(')'):
      message = message[4:-1]
    
    messageB = message.decode('base64')
    salt = messageB[0:self._blocksize]
    self._setPKCSKeys(salt)
    enc_text = messageB[self._blocksize:]

    cipher = DES.new(self._kv, DES.MODE_CBC, self._iv)
    res = cipher.decrypt(enc_text)

    padding = ord(res[-1])
    res = res[:-padding]

    return res

