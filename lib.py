import hashlib
import rsa
from exceptions import HashFunctionNotFound


def hash_data(data, hash_algorithm):
"""this function return hashed data with algorithm specified"""
  try:
    hash_function = getattr(hashlib, hash_algorithm)
  except AttributeError:
    raise HashFunctionNotFound
  encoded_data = data.encode("utf-8")
  return hash_function(encoded_data).digest()



def sign(data, private_key):
  """this function encrypt data with private key and return results"""
  return rsa.encrypt(data, private_key)
