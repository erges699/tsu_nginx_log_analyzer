"""
Используя любой скриптовый язык (Python, Ruby, Javascript, Perl) написать
скрипт для анализа лог файлов сервера nginx. Требуется определить Top-20
подозрительных запросов.
Определение подозрительности может осуществляться на основе black и white
листов. Требуется реализовать не менее 4 признаков(принадлежность к
определенному IP не может быть признаком). Запрос считается подозрительным
при совпадении не менее двух признаков.

Результат работы нужно продемонстрировать для предоставленного лог файла.
Работа сдается в виде:
1) одиночного файла скрипта, готового для запуска
2) указание на зависимые библиотеки (если есть)
3) скриншот и лог работы скрипта с выводом Top20 и для каждого
результата - перечисление на сработавшие признаки
Возможно предоставление решения в виде публичной песочницы, например на https://repl.it
"""
import re
import sys

from tqdm import tqdm


IP_PATTERN = '(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
DATE_TIME_PATTERN = '\[(?P<dateandtime>[^\]]+)\]'
REQUEST_PATTERN = '(?P<request>\"[^\"]+\"|"?")'
STATUS_CODE_PATTERN = '(?P<statuscode>\d{3})'
BYTES_SEND_PATTERN = '(?P<bytessent>\d+)'
REFERRER_PATTERN = '\"(?P<refferer>[^"]+)\"'
USER_AGENT_PATTERN = '\"(?P<useragent>[^"]+)\"'
LOG_PATTERN = re.compile(
    r''
    f'{IP_PATTERN} - - {DATE_TIME_PATTERN} {REQUEST_PATTERN} '
    f'{STATUS_CODE_PATTERN} {BYTES_SEND_PATTERN} {REFERRER_PATTERN} '
    f'{USER_AGENT_PATTERN}',
    re.IGNORECASE
)

REQUEST_ILLEGITIMACY_PATTERN = re.compile(
    r''
    '\/robots.txt|'
    '\/w00tw00t.at.ISC.SANS.DFind:\)|'
    'proxytest|'
    '\/home_page|'
    '\/phpmyadmin|'
    '\/testproxy.php|'
    '\/webdav|'
    'PROPFIND|'
    'HEAD|'
    '\/tmUnblock.cg|'
    'OPTIONS|'
    '\/API|'
    '\/Ringing.at.your.dorbell!|'
    'GET \/ HTTP|'
    '\/w00tw00t.at.ISC.SANS.DFind'
    '\/nice%20ports%2C\/Tri%6Eity.txt%2ebak',
    re.IGNORECASE
)
USER_AGENT_ILLEGITIMACY_PATTERN = re.compile(
    r''
    'Contact research@pdrlabs.net|'
    'masscan\/|'
    'WEBDAV Client|'
    'Mozilla/5.0|'
    'x00_-gawa.sa.pilipinas.2015|'
    '-',
    re.IGNORECASE
)
STATUS_ILLEGITIMACY_PATTERN = re.compile(
    r''
    '400|'
    '499|'
    '504|'
    '304',
    re.IGNORECASE
)
REQUEST_PATH_ILLEGITIMACY_PATTERN = re.compile(
    r''
    'google.com\/search?q=2+guys+1+horse',
    re.IGNORECASE
)
score_4_illegitimacy_list = []
score_3_illegitimacy_list = []
score_2_illegitimacy_list = []
score_1_illegitimacy_list = []
top_illegitimacy_list = {"4": 0, "3": 0, "2": 0, "1": 0}


def re_check(check_request, check_pattern):
    return check_pattern.search(check_request)


def checking_result(result):
    score = 0
    score_list = []
    request_illegitimacy = re_check(result[2], REQUEST_ILLEGITIMACY_PATTERN)
    status_illegitimacy = re_check(result[3], STATUS_ILLEGITIMACY_PATTERN)
    request_path_illegitimacy = re_check(
        result[5], REQUEST_PATH_ILLEGITIMACY_PATTERN
        )
    user_agent_illegitimacy = re_check(
        result[6], USER_AGENT_ILLEGITIMACY_PATTERN
        )

    if request_illegitimacy:
        score += 1
        score_list.append('request illegitimacy')
    if status_illegitimacy:
        score += 1
        score_list.append('status illegitimacy')
    if request_path_illegitimacy:
        score += 1
        score_list.append('request-path illegitimacy')
    if user_agent_illegitimacy:
        score += 1
        score_list.append('user-agent illegitimacy')

    return str(score), score_list


def parsing_log(log_line):
    match = LOG_PATTERN.findall(log_line)
    if not match:        
        print(log_line)
        raise RuntimeError("parsing failed")
    return list(match[0])


def append_score_list(score_list, value):
    return score_list.append(value)


def print_results():
    print(f'Запросов с 4 признаками подозрительности: '
          f'{len(score_4_illegitimacy_list)}')
    print(f'Запросов с 3 признаками подозрительности: '
          f'{len(score_3_illegitimacy_list)}')
    print(f'Запросов с 2 признаками подозрительности: '
          f'{len(score_2_illegitimacy_list)}')
    print(f'Запросов с 1 признаком подозрительности: '
          f'{len(score_1_illegitimacy_list)}')
    print('Топ 20 подозрительных запросов:')
    if len(
        score_4_illegitimacy_list
            ) == 0 and len(score_3_illegitimacy_list) > 20:
        for _ in score_3_illegitimacy_list[:21]:
            print(*_)


def main(file_path):
    with open(file_path, 'rt') as file_in:
        for log_line in tqdm(file_in, desc='Разбираю лог'):
            parsing_result = parsing_log(log_line)
            score = checking_result(parsing_result)
            if int(score[0]) == 4:
                append_score_list(
                    score_4_illegitimacy_list,
                    value=(score[1], tuple(parsing_result))
                    )
            elif int(score[0]) == 3:
                append_score_list(
                    score_3_illegitimacy_list,
                    value=(score[1], tuple(parsing_result))
                )
            elif int(score[0]) == 2:
                append_score_list(
                    score_2_illegitimacy_list,
                    value=(score[1], tuple(parsing_result))
                    )
            elif int(score[0]) == 1:
                append_score_list(
                    score_1_illegitimacy_list,
                    value=(score[1], tuple(parsing_result))
                    )


if __name__ == "__main__":
    LOG_FILE_PATH = sys.argv[1]
    main(LOG_FILE_PATH)
    print_results()
