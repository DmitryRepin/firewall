import argparse, logging, time
from datetime import datetime

from netfilterqueue import NetfilterQueue
from scapy.all import *
from subprocess import call, run

#Локальные модули
from imports.validator import *

logging.basicConfig(level=logging.INFO, filename="firewall.log", filemode="w")
interfaces_ip = get_interface_ip()
mode = ''


def bind_sockets(package):
    try:
        #Создание сокета для приема пакетов (исходящих и входящих)
        raw_data = IP(package.get_payload())
        s_addr = raw_data.src
        d_addr = raw_data.dst
        protocol = 1
        if raw_data.haslayer(TCP):
            packet = raw_data.getlayer(TCP)
            src_port = packet.sport
            dst_port = packet.dport 
            protocol = 8
        if raw_data.haslayer(UDP):
            packet = raw_data.getlayer(UDP)
            src_port = packet.sport
            dst_port = packet.dport
            protocol = 17

        if s_addr in interfaces_ip:
            result = validate_with_rules(s_addr, d_addr, src_port, dst_port, 'output')
        else:
            result = validate_with_rules(s_addr, d_addr, src_port, dst_port, 'input')

        if mode == 'white':
            if result == True:
                package.accept()
            else:
                package.drop()
                logging.error(f"<Соединение заблокировано>[{datetime.now()}] ({s_addr}, {d_addr}) >  {protocol}")
        elif mode == 'black':
            if result == True:
                package.drop()
                logging.error(f"<Соединение заблокировано>[{datetime.now()}] ({s_addr}, {d_addr}) >  {protocol}")
            else:
                package.accept()
                
        #    package.drop()
        #else:
        #    #logging.info(f"[{datetime.now()}] ({s_addr}) >  {src_port}")
        #    package.accept()

    except KeyboardInterrupt:
        print("\nОстановлен")
        return

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Межсетевой экран. Репин Дмитрий')
    parser.add_argument("-A", "--add", help="Добавление правила (для исходящих или входящих подключений)", choices=['input', 'output'])
    parser.add_argument("-D", "--delete", help="Удаление правила", choices=['input', 'output'])
    parser.add_argument("-I", "--ip", help="IP-адрес")
    parser.add_argument("-P", "--port", help="Порт")
    parser.add_argument("--delete-all", help="Удаление всех правил", action="store_true")
    parser.add_argument("-L", "--list", help="Отобразить правила", action="store_true")
    parser.add_argument("-S", "--start", help="Запуск межсетевого экрана (режиме белого или черного списка)", choices=['white', 'black'])
    args = parser.parse_args()

    #Отобразить правила
    if args.list:
        print_rules()
        exit(1)

    #Удаление всех правил
    if args.delete_all:
        delete_all_rules()
        print('Все правила межсетеого экрана удалены...')
        exit(1)

    #Добавление правила
    if args.add:
        if args.ip:
            num_ip = args.ip.split('.')
            if len(num_ip) == 4:
                for num in num_ip:
                    try:
                        if int(num)>255:
                            print('Указанный ip-адрес некорректен...')
                            exit(1)
                    except ValueError as e:
                        print('Указанный ip-адрес некорректен...')
                        exit(1)
            else:
                print('Указанный ip-адрес некорректен...')
                exit(1)

            if not args.port:
                args.port = 'any'
 
        elif args.port:
            if not args.ip:
                args.ip = 'any'
            
        else:
            print('Необходимо указать ip-адрес или порт для создания правила...')
            exit(1)  
        
        add_new_rule(args.ip, args.port, args.add)
        exit(1)
    
    #Удаление правила
    if args.delete:
        if args.ip:
            num_ip = args.ip.split('.')
            if len(num_ip) == 4:
                for num in num_ip:
                    try:
                        if int(num)>255:
                            print('Указанный ip-адрес некорректен...')
                            exit(1)
                    except ValueError as e:
                        print('Указанный ip-адрес некорректен...')
                        exit(1)
            else:
                print('Указанный ip-адрес некорректен...')
                exit(1)

            if not args.port:
                args.port = 'any'
 
        elif args.port:
            if not args.ip:
                args.ip = 'any'
            
        else:
            print('Необходимо указать ip-адрес или порт для удаления правила...')
            exit(1)  
        
        delete_rule(args.ip, args.port, args.delete)
        exit(1)
        
    if args.start:
        print("Межсетевой экран запущен... ")

        mode = args.start
        if mode == 'white':
            print('Режим белого списка...')
        elif mode == 'black':
            print('Режим черного списка...')
        call('/sbin/iptables-restore < /etc/iptables-conf/iptables_rules.ipv4', shell=True)      
        nfqueue = NetfilterQueue()
        nfqueue.bind(1, bind_sockets)
        
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            print("\nЗавершение работы межсетевого экрана...")
            nfqueue.unbind()
            exit(1)
        