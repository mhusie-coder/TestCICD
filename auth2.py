import requests
import jwt
import json
import time
import os
from dotenv import dotenv_values
class Auth2Token():
    def __init__(self, path):
        self.path = path # path to private key file
    def generate_jwt_token(self): # method for generating JWT token based on creditionals of service account in order to get access token
        config = dotenv_values(".env2") # load data from env file into dict  
        claims = {
            "iss": config["ISS"],
            "scope": config["SCOPE"],
            "aud": config["AUD"],
            "exp": time.time() + 3600,
            "iat": time.time()
        }
        headers = {
            "alg": config["ALG"],
            "typ": config["TYPE"], 
            "kid":config["KID"]
        }
        private_key = open(self.path, "rb")
        content = private_key.read() # read data from file
        encoded = jwt.encode(payload=claims,key=content,headers=headers) # generating jwt token
        private_key.close()
        return encoded
    def get_access_token(self):
        if os.path.exists("./.token"):
            access_token_file = open("./.token", "r")
            content_access_token = access_token_file.read() 
            access_token_file.close()
            return content_access_token
        else:
            raise LookupError("Error occured because file into ./.token doesn't exist(Generate file first)")
    def generate_new_access_token(self):
        jwt_token = self.generate_jwt_token()
        headers = {'Content-Type': 'application/x-www-form-urlencoded', "Host": "oauth2.googleapis.com"}
        data = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="+jwt_token
        response = json.loads(requests.post("https://oauth2.googleapis.com/token", data=data, headers=headers).text) ## make post request and parse response into json format
        access_token_file = open("./.token", "w")
        access_token_file.write(response["access_token"]) # write access token to file
        access_token_file.close()
if __name__ == "__main__":
    auth = Auth2Token("key2.pem")
    auth.generate_new_access_token()
    print(auth.get_access_token())

