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

def get_api_key(ti_systems):
    api_key = os.getenv('API_KEY_' + ti_systems)

    if not api_key:
        print("Введи API ключ для ", ti_systems)
        api_key = input()
        with open('.env', 'a') as env_file:
            name_api_env = 'API_KEY_' + ti_systems
            env_file.write(f'{name_api_env}={api_key}\n')
        
        print("API ключ сохранен в переменной окружения\n")
    else:
        print("API ключ загружен из переменной окружения\n")
    
    return api_key

print("\nAPI ключ для VirusTotal\n")
ti_vt = 'VirusTotal'
api_vt = get_api_key(ti_vt)

print("API ключ для KTI\n")
ti_ktip = 'KTIP'
api_ktip = get_api_key(ti_ktip)

# WHOIS - information about IPv4 address

def whois(add):
    print("WHOIS\n")

    lnk = "http://ip-api.com/json/"+add
    response = requests.get(lnk)
    p = response.text
    text = json.loads(p)
    print(f"Код страны: {text['countryCode']}\n"
          f"Страна: {text['country']}\n"
          f"Город: {text['city']}\n"
          f"Координаты расположения:\n\t lat: {text['lat']}\n\t lon: {text['lon']}\n"
          f"Провайдер: {text['as']}\n")
    

# Формирование GET запроса для получения ответа о запрашиваемом адресе

def api_get(add, url, api):

    api_url = url + add

    if api == api_vt:
        headers_api = {"x-apikey": api}
    elif api == api_ktip:
        headers_api = {"x-api-key": api}

    response = requests.get(api_url, headers = headers_api)
    json_text = json.loads(response.text)

    return json_text

# Форматирование json

def format_json(stats):
    return json.dumps(stats, indent=4, ensure_ascii=False)


# VirusTotal - предоставление информации об IP адресе 

def virustotal(add, api):
    print("\nVirusTotal")
    url = 'https://www.virustotal.com/api/v3/ip_addresses/'
    rep = api_get(add, url, api)['data']['attributes']['last_analysis_stats']['malicious']
    
    if rep == 0:
        print("Репутация адреса: надежный")
    else:
        print("Репутация адреса: ненадежный!") 
    
    stats = api_get(add, url, api)['data']['attributes']['last_analysis_stats']    
    my_time = api_get(add, url, api)['data']['attributes']['last_modification_date']

    print(f"Статистика адреса: \n{format_json(stats)}\n"
          f"Дата последнего анализа: {time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(my_time))}\n")
    
    return rep
    
#Kaspersky Threat Intelligence Portal - предоставление информации об IP адресе 

def ktip(add, api):
    print("Kaspersky Threat Intelligence Portal\n")
    url = 'https://opentip.kaspersky.com/api/v1/search/ip?request='
    
    rep = api_get(add, url, api)["Zone"]
    print("Уровень опасности: \n", rep)
    if rep != 'Green' and rep != 'Grey':
       categories = api_get(add, url, api)["IpGeneralInfo"]["CategoriesWithZone"]
       print(f"Вывод: адрес ненадежный!\n"
             f"Категория опасности: {format_json(categories)}\n") 
       if rep == 'Orange':
           dang = 2
       elif rep == 'Red':
           dang = 3
    elif rep == 'Grey':
        print("Адрес не известен\n")
        dang = 1
    else:
        print("Вывод: адрес надежный\n")
        dang = 0

    return dang



whois(ip)
vt = virustotal(ip, api_vt)
kasp = ktip(ip, api_ktip)
if vt == kasp and vt == 0:
    print(f"Итоговый вывод по адресу {ip}: надежный!")
elif vt != kasp and (vt == 0 or kasp == 0):
    print(f"Итоговый вывод по адресу {ip}: точно определить затруднительно, требуется дополнительный анализ")
else:
    print(f"Итоговый вывод по адресу {ip}: ненадежный!") 