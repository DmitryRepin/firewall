#Update
import csv, psutil

def get_interface_ip():
    #Получение сведений об интефейсах 
    add = psutil.net_if_addrs()
    try:
        interfaces_ip = []
        for key in add.keys():
            if key == "lo":
                continue
            else:
                interface_ip = addrs[key][0].address
                interfaces_ip.append(interface_ip)
        return interfaces_ip

    except Exception as e:
        print(f"Ошибка полученияsadsdasd сведений об сетевых интерфейсах: {e}")
        exit(1)


def check_rules(ip_addr, port, conn_type):
    with open('./imports/Rules.csv', 'r') as rules_stream:
        rules = csv.reader(rules_stream)

        id_rules = []

        for num, rule in enumerate(rules):
            # <CONN_TYPE> <IP> <PORT> 
            #Провкрка типа соединения
            if conn_type == str(rule[0]):
                #Проверка ip-адреса
                if rule[1] == ip_addr and rule[2] == port:
                    id_rules.append(num)
                elif rule[1] == ip_addr and port == 'any':
                    id_rules.append(num)
                elif rule[2] == port and ip_addr == 'any':
                    id_rules.append(num)

    return id_rules


def print_rules():
    with open('./imports/Rules.csv', 'r') as rules_stream:
        rules = csv.reader(rules_stream)
        print('Правила межсетевого экрана...\n')
        print('Правила для входящих соединений')
        print('%17s %7s' % ('ip-адрес', 'порт'))
        for rule in rules:
            if rule[0] == 'input':
                ip_addr = 'Любой' if rule[1] == 'any' else rule[1]
                port = 'Любой' if rule[2] == 'any' else rule[2]
                print('[%15s] [%5s]' % (ip_addr, port))
        print('\nПравила для исходящий соединений')
        print('%17s %7s' % ('ip-адрес', 'порт'))
        for rule in rules:
            if rule[0] == 'output':
                ip_addr = 'Любой' if rule[1] == 'any' else rule[1]
                port = 'Любой' if rule[2] == 'any' else rule[2]
                print('[%15s] [%5s]' % (ip_addr, port))


def add_new_rule(ip_addr, port, conn_type):
    if len(check_rules(ip_addr, port, conn_type)) == 0:
        with open('./imports/Rules.csv', 'a', newline='') as rules_stream:
            rule = [str(conn_type), str(ip_addr), str(port)]
            rules = csv.writer(rules_stream)
            rules.writerow(rule)
        conn_type = 'Исходящее соединение' if conn_type == 'output' else 'Входящее соединение'
        ip_addr = 'Любой' if ip_addr== 'any' else ip_addr
        port = 'Любой' if port == 'any' else port
        print('Добавлено новое правило:')
        print(f'{conn_type}: ip-адрес - [{ip_addr}]; порт - [{port}]')
    
    else:
        print(f'Правило [ip-адрес - {ip_addr}, порт - {port}] уже существует')


def delete_all_rules():
    with open('./imports/Rules.csv', 'w') as rules_stream:
        rules = csv.writer(rules_stream)
        rules.writerow([])
    print('Все правила удалены...')
        

def delete_rule(ip_addr, port, conn_type):
    found_rules = check_rules(ip_addr, port, conn_type)
    if len(found_rules) > 0:
        with open('./imports/Rules.csv', 'r', newline='') as rules_stream:
            all_rules = list(csv.reader(rules_stream))

        print('Удалены правила: ')
        new_rules = []
        for num, rule in enumerate(all_rules):
            if num in found_rules:
                print_ip = 'Любой' if rule[1] == 'any' else rule[1]
                print_port = 'Любой' if rule[2]== 'any' else port
                print_type = 'Исходящее соединение' if conn_type == 'output' else 'Входящее соединение'
                print(f'{print_type}: ip-адрес - [{print_ip}], port - [{print_port}]')
            else:
                new_rules.append((rule))

        with open('./imports/Rules.csv', 'w', newline='') as rules_stream:
            rules = csv.writer(rules_stream)
            for rule in new_rules:
                rules.writerow(rule)
    
    else:
        print('Правил для удаления не найдено')
        

def validate_with_rules(src_addr, dst_addr, src_port, dst_port, action):
    try:
        rules_stream = open("./imports/Rules.csv", "r")
        rules = csv.reader(rules_stream)

        for rule in rules:
            # <CONN_TYPE> <IP> <PORT> 
            if action == 'input':
                ip_addr = src_addr
                port = src_port
            elif action == 'output':
                ip_addr = dst_addr
                port = dst_port
                
            if rule[0] == action:
                if rule[1] == ip_addr:
                    if rule[2] == str(port):
                        return True
                elif rule[2] == str(port):
                    if rule[1] == 'any':
                        return True

        return False

    except Exception as e:
        print(f"[ERR] Ошибка чтения файла: {e}")
        return False
