import requests
import json
#import linecache
import time
import os
from dotenv import load_dotenv

# Ввод IPv4 - адреса

print("Введите IP адрес, который нужно проверить: ")
ip = input()

# Загрузка из .env в среду выполнения 

load_dotenv() 

# Получения нужного API ключа

def get_api_key(api_key, ti_systems):
    api_key = os.getenv('API_KEY_'+ti_systems)

    if not api_key:
        print("Введи API ключ для ", ti_systems)
        api_key = input()
        with open('.env', 'a') as env_file:
            name_api_env = 'API_KEY_'+ti_systems
            env_file.write(f'{name_api_env}={api_key}\n')
        
        print("API ключ сохранен в переменной окружения.")
    else:
        print("API ключ загружен из переменной окружения.")
    
    return api_key

print("API ключ для VirusTotal")
ti_vt = 'VirusTotal'
api_vt = 0
api_vt = get_api_key(api_vt, ti_vt)

print("API ключ для KTI")
ti_ktip = 'KTIP'
api_ktip = 0
api_ktip = get_api_key(api_ktip, ti_ktip)

# WHOIS - information about IPv4 address

def whois(add):
    print("WHOIS")

    lnk = "http://ip-api.com/json/"+add
    response = requests.get(lnk)
    p = response.text
    text = json.loads(p)

    country_code = text['countryCode']
    print("Код страны: ", country_code)

    country = text['country']
    print("Страна: ", country)
    
    city = text['city']
    print("Город: ", city)
    
    coordinate1 = text['lat']
    coordinate2 = text['lon']
    print("Координаты расположения: \n lat: ", coordinate1, "\n lon: ", coordinate2)
    
    provider = text['as']
    print("Провайдер: ", provider, "\n")

# Формирование GET запроса для получения ответа о запрашиваемом адресе

def api_get(add, url, api):

    api_url = url+add

    if api == api_vt:
        headers_api = {"x-apikey": api}
    elif api == api_ktip:
        headers_api = {"x-api-key": api}

    response = requests.get(api_url, headers = headers_api)
    json_text = json.loads(response.text)

    return json_text

# Форматирование json

def format_json(stats):
    result_str = json.dumps(stats, indent=4, ensure_ascii=False)
    return result_str


# VirusTotal - предоставление информации об IP адресе 

def virustotal(add, api):
    print("\nVirusTotal")
    url = 'https://www.virustotal.com/api/v3/ip_addresses/'
    rep = api_get(add, url, api)['data']['attributes']['last_analysis_stats']['malicious']
    
    if rep == 0:
        print("Репутация адреса: надежный")
    else:
        print("Репутация адреса: ненадежный!") 
    
    print("Статистика адреса: ")

    stats = api_get(add, url, api)['data']['attributes']['last_analysis_stats']
    print(format_json(stats))
    
    my_time = api_get(add, url, api)['data']['attributes']['last_modification_date']
    print("Дата последнего анализа: ", time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(my_time)))
    print('\n')
    
#Kaspersky Threat Intelligence Portal - предоставление информации об IP адресе 

def ktip(add, api):
    print("Kaspersky Threat Intelligence Portal\n")
    url = 'https://opentip.kaspersky.com/api/v1/search/ip?request='
    
    rep = api_get(add, url, api)["Zone"]
    print("Уровень опасности: ", rep)
    if rep != 'Green' or rep != 'Grey':
       print("Вывод: адрес ненадежный!")
       categories = api_get(add, url, api)["IpGeneralInfo"]["CategoriesWithZone"]
       print("Категория опасности: ", format_json(categories)) 
    else:
        print("Вывод: адрес надежный")



whois(ip)
virustotal(ip, api_vt)
ktip(ip, api_ktip)