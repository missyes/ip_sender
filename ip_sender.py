#!/bin/python
import random
import vk
import requests
token=''
client=
r = requests.request('GET', 'http://myip.dnsomatic.com') #http://suip.biz/ip/
ip = r.text
session=vk.Session(access_token=token)
api=vk.API(session)
api.messages.send(user_id=client, message=ip,random_id=random.randint(100000,99999999),v=5.92)
print("Done")
