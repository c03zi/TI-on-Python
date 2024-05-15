import requests
import json
import linecache
import time

# whois
print("Введите IP адрес, который нужно проверить: ")
ip = input()
print("WHOIS")
lnk = "http://ip-api.com/json/"+ip
response = requests.get(lnk)
p = response.text
text = json.loads(p)
countryCode = text['countryCode']
print("Код страны: ", countryCode)
country = text['country']
print("Страна: ", country)
city = text['city']
print("Город: ", city)
coordinate1 = text['lat']
coordinate2 = text['lon']
print("Координаты расположения: \n lat: ", coordinate1, "\n lon: ", coordinate2)
provider = text['as']
print("Провайдер: ", provider)
print("\n")



print("----------------------------------------")
print("VIRUSTOTAL")
#virustotal
print("Введите API Key от VirusTotal")
api_key = input()
print("\n")
api_url = 'https://www.virustotal.com/api/v3/ip_addresses/'+ip
headers = {"x-apikey": api_key}
response = requests.get(api_url, headers = headers)
vt = json.loads(response.text)
rep = vt['data']['attributes']['last_analysis_stats']['malicious']
if rep == 0:
    print("Репутация сайта: надежный")
else:
    print("Репутация сайта: ненадежный!") 
print("Статистика сайта: ")
stats = vt['data']['attributes']['last_analysis_stats']
def format_json(stats):
    resultStr = json.dumps(stats, indent=4, ensure_ascii=False)
    return resultStr
print(format_json(stats))
my_time = vt['data']['attributes']['last_modification_date']
print("Дата последнего анализа: ", time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(my_time)))
print('\n')
print("----------------------------------------")



#AlienVault OTX
print("AlienVault OTX \n")
alien_url = 'https://otx.alienvault.com/api/v1/indicators/IPv4/'+ip+'/reputation'
#print("Введите API Key от AlienVault OTX")
#api_key = input()
headers = {"x-apikey": api_key}
response = requests.get(alien_url, headers=headers)
text_av = response.text
def format_json(text_av):
    resultStr = json.dumps(json.loads(text_av), indent=4, ensure_ascii=False)
    return resultStr
print(format_json(text_av))
print('\n')



print("----------------------------------------") 
#Shodan
print("SHODAN \n")
print("Введите API Key для Shodan")
api_shodan = input()
shodan_url = 'https://api.shodan.io/shodan/host/'+ip+'?key='+api_shodan
response = requests.get(shodan_url)
text_sh = response.text
base = json.loads(text_sh)
open_ports = base['ports']
print("Открытые порты: ", open_ports)
http_status = base['data'][2]['http']['status']
print("Код http-ответа: ", http_status)
