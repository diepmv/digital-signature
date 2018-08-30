import base64

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import xml.etree.ElementTree as ET


msg = 'test message'


xml_string_publickey = '''
<publickeyN>
	<dataLength>512</dataLength>
	<dataType>B</dataType>
	<binaryData>ZDQwOTlkOTNkMTVmY2ZlNDU1NTE2ODAyMDg3NGJjMTc4YmNmYTBmOGMwZTY2M2ExYzNiMTg1NTJiMjA2ZDNkYTY4YTY0ODVkNjA3ZTdlNjQyNzA2YTQzY2JhNDk4YzIyZWVhNzA4ZDhkYTRlYjVmZjBjOGRiYjA2ZjkzNTZkYmU2OGM1NGRkMjdiMjc4Y2RlYTlhNzY1ZjI3MTkwODFlZDdlYzA4YjQ1Nzc4M2QzYzczM2EwOTc0NGY3MmIwYjk5ZmZhZWMwMWMyODc0ODBlZTFjZmI3OThmYTVlOThhZWEzMDJmMDNjYzk4NzkzNmQ3ZTkxNGIwMjU1ZTFjYTdiZTQ3Yjk5OGFiOTM0N2JiOGM3OTU2MDY0ODg2NTcwNTQ4NjIxNjY0NzBiMWIwZjE0ZmU4NmZkMmIxMTk0ZTc2ZWQ5OTg5YTgwZTQyYjczYjRhMzdkYzYzMTU1NWJlNGFhNWY4YzcwZTU1MGNhOTg4NGRmNjgwNDU0ZGRjY2QwNWRkYmQ2NjNmNjI3NmRkYjIwMzg0M2UyOGMxZjM4MmI4MjQ4NDhhYWQxNjM2ZjQ5NDg3NmZlMTM0MWJmNzU1NmIxOWYwN2JkOWY2MjlkYWQyNWFjN2ZkODk0OGMwYTYxZTU3NWQ3YzU0N2U5MGIyNzI1ZmI0YmJhNDEyZmMyNWIyNmQ=</binaryData>
</publickeyN>
<publickeyE>
	<dataLength>6</dataLength>
	<dataType>B</dataType>
	<binaryData>MDEwMDAx</binaryData>
</publickeyE>'''


xml_string_publickey = '<root>' + xml_string_publickey + '</root>'

root = ET.fromstring(xml_string_publickey)

modulus = root.find('publickeyN').find('binaryData').text
exponent = root.find('publickeyE').find('binaryData').text

# function convert base64 encoded value to long int
def b64tolongInt(base64value):
	value = base64.b64decode(base64value)
	return long(value, 16)

modulus = b64tolongInt(modulus)

exponent = b64tolongInt(exponent)

# construct pub key
pubkey = RSA.construct((modulus, exponent))


cipher = PKCS1_v1_5.new(pubkey)
ciphertext = cipher.encrypt(msg)

#encode ciphertext using base64
ciphertext = base64.b64encode(ciphertext)
print(ciphertext)
