import hashlib
from keys import PUB_KEY
from keys import PRI_KEY
from lib import hash_data
from lib import sign
from future.builtins import input

def main():
  while True:
    #Data input
    data = input("Enter data to encode:")
    #Data after hashing
    hashed_data = hash_data(data, "sha256")
    #Signature after sign with private key
    signature = sign(hashed_data, PRI_KEY)




if __name__ == "__main__":
  main()
