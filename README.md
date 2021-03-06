# Как мы выбирали VPN-протокол и сервер настраивали

## Зачем всё это и для чего?

У нас было: 10 самых простых конфигураций серверов на DigitalOcean, мобильные устройства на базе iOS, сервер для сбора статистики, никакого опыта в настройке VPN-серверов, а так же неукротимое желание сделать быстрый, надёжный и простой в использовании VPN-сервис, которым будет приятно пользоваться. Не то, чтобы всё это было категорически необходимо, но если уж начали, то к делу надо подходить серьёзно.

В этой стетье кратко опишу как мы выбирали VPN-протокол, как настраивали сервер и как оранизовали сбор статистики с каждого VPN-сервера. Не стоит рассчитывать на подробную пошаговую инстуркцию. В статье я буду приводить отрывки из файлов конфигураций с краткими коментариями.

Я думаю что в IT сфере уже не найти человека который не знал бы, что такое VPN и зачем он нужен.
Но если тезисно объяснять зачем нужен VPN современному человеку, то получится примерно следующее:
* Если у вас есть какие-то внутренние (приватные) ресурсы, доступ к которым должен быть ограничен из глобальной сети интернет.
* Если вам необходимо организовать защищенное соединение между двумя сетями.
* Если вам нужно получить доступ к ресурсам, которые по тем или иным причинам недоступны из вашей страны (меняется ваше местоположение относительно вашего IP-адреса).

И не совсем очевидный момент, скорость интернет соединения может быть выше через vpn, т.к. ваш провайдер может отправить ваш трафик по более короткому маршруту, а значит более оптимальному маршруту, из-за этого вы и можете получить прирост в скорости. Но это может сработать и в обратную сторону, если вы выберете не очень удачное расположение сервера относительно вас (об этом немного позже).

## Как мы выбирали VPN-протокол

VPN-протокол должен без проблем поддерживаться на мобильных устройствах, без установки дополнительного программного обеспечения.
Мы выбрали самые известные реализации протоколов и отсеяли не подходящие по условиям исходной задачи.
А условия всего два, я напомню:
* Стабильное и надёжное подключение.
* Без установки стороннего программного обеспечения на устройство клиента.

Пробегусь по протоколам и кратко расскажу о них + расскажу причины почему тот или иной протокол нам не подошёл.

### PPTP (Point-To-Point Tunneling Protocol)

Один из самых старейших VPN протоколов, разработанный компанией Microsoft. Из-за солидного возраста протокол поддерживается большинством операционных систем, но в тоже время не может обеспечить стабильное и надёжное соединение. Компания Microsoft советует использовать L2TP или SSTP на замену PPTP.
Этот протокол прост в настройке и не требователен к ресурсам сервера, но проблемы с безопасностью заставляют отказаться от его использования в наших целях.

### L2TP/IPSec

Протокол во многом схож с PPTP, разрабатывался и принимался практически одновременном с ним. Этот протокол более требователен к вычислительным мощностям, часто используется интернет провайдерами, т.к. считается более эффективным для построения виртуальных сетей.
L2TP/IPsec позволяет обеспечить высокую безопасность данных, поддерживается всеми современными операционными системами. Есть одно НО, инкапсулирует передаваемые данные дважды, что делает его менее эффективным и более медленным, чем другие VPN-протоколы.
От этого протокола пришлось отказаться т.к. он более требователен к вычислительным мощностям сервера, а значит велик риск получить стабильное НО медленное соединение, что может огорчить пользователей.

### IKEv2/IPSec

Был разработан Microsoft совместно с Cisco, существуют реализации протокола с открытым исходным кодом (например, OpenIKEv2, Openswan и strongSwan).
Поддерживает Mobility and Multi-homing Protocol (MOBIKE), что обеспечивает устойчивость к смене сетей.
IKEv2 очень хорошо подходит для использования на мобильных устройствах, которые чаще всего склонны к переключению между WiFI и мобильным интернетом.
IKEv2 имеет нативную поддержку в большинстве операционных систем.
Вот этот вариант нам уже больше подходит, т.к. поддержка Mobility and Multi-homing Protocol будет очень большим плюсом при использовании на мобильных устройствах.

### OpenVPN
Разработан компанией OpenVPN Technologies.
Протокол с открытым исходным кодом, который прошёл все возможные проверки безопасности.
Протокол OpenVPN стабилен и может обеспечить хорошую скорость передачи данных. Ещё одно преимущество протокола, что он для работы использует стандартные протоколы TCP и UPD, а также может работать на любом из портов, это усложняет блокировку VPN сервиса провайдерами.
Для подключения к сети с использованием OpenVPN, необходимо устанавливать дополнительное программное обеспечение, чтобы бывает иногда затруднительно или невозможно.
Этот вариант нам бы тоже подошёл, но к сожалению из-за необходимости установки клиента, придётся отказаться от этого протокола.

### Wireguard

На данный момент, это самый свежий протокол VPN. Его часто сравнивают с IPSec и OpenVPN, и нарекают его как замену этим двум протоколам, но он всё ещё слишком сырой, чтобы использовать его в больших масштабах.
Лучшие результаты этот протокол показывает на Unix системах, т.к. он реализован в виде модуля ядра Unix. Но, эта высокая пропускная способность достигается за счёт замедления сетевой активности других приложений.
Чтобы настроить на своём мобильном устройстве данный протокол, необходимо будет установить клиент, что тоже не всегда возможно в силу обстоятельств.
И вот опять, необходимость установки дополнительного клиента на устройство отметает все шансы на использование этого протокола в наших целях.

В итоге, мы решили остановится на **IKEv2/IPSe**, по следующим причинам:
* Поддержка Mobility and Multi-homing Protocol (MOBIKE).
* Нативная поддержка в большинстве операционных систем.
* Обеспечивает высокую скорость соединения.
* Не требователен к ресурсам сервера.

Перейдём от теории к практике.

## Настраиваем VPN-сервер

Прежде чем приступить к настройке сервера, необходимо определиться где мы будем размещать наш(ы) сервер(а).
Самый простой критерий выбора расположения сервера, это удалённость от вас, т.е. если будет выбор между размещением сервера в германии или в США, то своё предпочтение следует отдать Германии (если вы находитель в России), т.к. в теории ваш трафик будет проходить через меньшее кол-во магистралей и будет идти по более короткому маршруту.

Для личного использования или небольшого кол-ва пользователей подойдёт самый простой вариант сервера, к примеру на digitalocean можно взять самую базовую конфигурацию сервера с одним ядром, 1 Gb оперативной памяти и 25 Gb дискового пространства.

От слов к практике, каких-то особых навыков и тайных знаний для настройки VPN-сервера не понадобится.

Для установки и настройки сервера будем использовать следующие инструменты:
* Docker + docker-compose.
* strongswan - реализацию IPSec сервера.
* Let's Encrypt - для генерации сертификатов.
* Radius - для мониторинга и отправки статистических данных.

Начнём с Docker контейнера, в котором и будет запускаться vpn-сервер.

**Docker.file** ([полная версия](https://github.com/appbooster/docker-ikev2-vpn-server/blob/master/Dockerfile))

    FROM alpine:latest #сервер будем собирать на основе образа alpine-linux

    ...
    # strongSwan Version
    ARG SS_VERSION="https://download.strongswan.org/strongswan-5.8.2.tar.gz" #версию можете выбрать сами, исходя из того когда вы читаете данную статью.

    ...

    COPY ./run.sh /run.sh
    COPY ./adduser.sh /adduser.sh
    COPY ./rmuser.sh /rmuser.sh

    RUN chmod 755 /run.sh /adduser.sh /rmuser.sh

    VOLUME ["/usr/local/etc/ipsec.secrets"]

    EXPOSE 500:500/udp 4500:4500/udp

    CMD ["/run.sh"]
    
Для управления пользователями мы создаём два скрипта *adduser.sh*, *rmuser.sh* для добавления и удаления пользователя соответственно.

**adduser.sh**

    #!/bin/sh

    VPN_USER="$1"

    if [ -z "$VPN_USER" ]; then
      echo "Usage: $0 username" >&2
      echo "Example: $0 jordi" >&2
      exit 1
    fi

    case "$VPN_USER" in
      *[\\\"\']*)
        echo "VPN credentials must not contain any of these characters: \\ \" '" >&2
        exit 1
        ;;
    esac

    VPN_PASSWORD="$(openssl rand -base64 9)" #генерируем пароль для пользователя
    HOST="$(printenv VPNHOST)"

    echo "Password for user is: $VPN_PASSWORD"
    echo $VPN_USER : EAP \"$VPN_PASSWORD\">> /usr/local/etc/ipsec.secrets # сохраняем имя пользователя и пароль в файл /usr/local/etc/ipsec.secrets

    ipsec rereadsecrets
    
**rmuser.sh**

    #!/bin/sh

    VPN_USER="$1"

    if [ -z "$VPN_USER" ]; then
      echo "Usage: $0 username" >&2
      echo "Example: $0 jordi" >&2
      exit 1
    fi

    cp /usr/local/etc/ipsec.secrets /usr/local/etc/ipsec.secrets.bak
    sed "/$VPN_USER :/d" /usr/local/etc/ipsec.secrets.bak > /usr/local/etc/ipsec.secrets # удаляем строку и спользователем из файла /usr/local/etc/ipsec.secrets

    ipsec rereadsecrets
    
На сервере все пользователи будут храниться в файле **ipsec.secrets**.

Для запуска нашего сервера подготовим следующий скрипт:
    
**run.sh** [полная версия](https://github.com/appbooster/docker-ikev2-vpn-server/blob/master/run.sh)

    #!/bin/bash

    VPNIPPOOL="10.15.1.0/24" # указываем из какого диапазона будут выдаваться IP нашим клиентам, которые будут подключаться к VPN-серверу.
    LEFT_ID=${VPNHOST}       # домен нашего vpn-сервера

    sysctl net.ipv4.ip_forward=1
    sysctl net.ipv6.conf.all.forwarding=1
    sysctl net.ipv6.conf.eth0.proxy_ndp=1

    if [ ! -z "$DNS_SERVERS" ] ; then # можем указать свои DNS сервера, которые будут использоваться в vpn сервере.
    DNS=$DNS_SERVERS
    else
    DNS="1.1.1.1,8.8.8.8"
    fi

    if [ ! -z "$SPEED_LIMIT" ] ; then # для того, чтобы один пользователь не "съел" весь канал, можем ограничить скорость пользователя до указанной величины.
    tc qdisc add dev eth0 handle 1: ingress
    tc filter add dev eth0 parent 1: protocol ip prio 1 u32 match ip src 0.0.0.0/0 police rate ${SPEED_LIMIT}mbit burst 10k drop flowid :1
    tc qdisc add dev eth0 root tbf rate ${SPEED_LIMIT}mbit latency 25ms burst 10k
    fi

    iptables -t nat -A POSTROUTING -s ${VPNIPPOOL} -o eth0 -m policy --dir out --pol ipsec -j ACCEPT
    iptables -t nat -A POSTROUTING -s ${VPNIPPOOL} -o eth0 -j MASQUERADE

    iptables -L
  
    # Здесь мы генерируем сертификат сервера
    if [[ ! -f "/usr/local/etc/ipsec.d/certs/fullchain.pem" && ! -f "/usr/local/etc/ipsec.d/private/privkey.pem" ]] ; then
        certbot certonly --standalone --preferred-challenges http --agree-tos --no-eff-email --email ${LEEMAIL} -d ${VPNHOST}
        cp /etc/letsencrypt/live/${VPNHOST}/fullchain.pem /usr/local/etc/ipsec.d/certs
        cp /etc/letsencrypt/live/${VPNHOST}/privkey.pem /usr/local/etc/ipsec.d/private
        cp /etc/letsencrypt/live/${VPNHOST}/chain.pem /usr/local/etc/ipsec.d/cacerts
    fi

    rm -f /var/run/starter.charon.pid
    
    # Настройка непосредственно ipsec сервера
    if [ -f "/usr/local/etc/ipsec.conf" ]; then
    rm /usr/local/etc/ipsec.conf
    cat >> /usr/local/etc/ipsec.conf <<EOF
    config setup
        charondebug="ike 1, knl 1, cfg 1"
        uniqueids=never
        conn ikev2-vpn
       	...
        
        eap_identity=%identity
    EOF
    fi

    if [ ! -f "/usr/local/etc/ipsec.secrets" ]; then
    cat > /usr/local/etc/ipsec.secrets <<EOF
    : RSA privkey.pem
    EOF
    fi
    
    .....
    EOF
    fi
    sysctl -p

    ipsec start --nofork

Чтобы было проще запустить весь сервер одной командой, завернём всё в docker-compose:
    
    version: '3'

    services:
      vpn:
        build: .
        container_name: ikev2-vpn-server
        privileged: true
        volumes:
          - './data/certs/certs:/usr/local/etc/ipsec.d/certs'
          - './data/certs/private:/usr/local/etc/ipsec.d/private'
          - './data/certs/cacerts:/usr/local/etc/ipsec.d/cacerts'
          - './data/etc/ipsec.d/ipsec.secrets:/usr/local/etc/ipsec.secrets'
        env_file:
          - .env
        ports:
          - '500:500/udp'
          - '4500:4500/udp'
          - '80:80'
        depends_on:
          - radius
        links:
          - radius
        networks:
          - backend

      radius:
        image: 'freeradius/freeradius-server:latest'
        container_name: freeradius-server
        volumes:
          - './freeradius/clients.conf:/etc/raddb/clients.conf'
          - './freeradius/mods-enabled/rest:/etc/raddb/mods-enabled/rest'
          - './freeradius/sites-enabled/default:/etc/raddb/sites-enabled/default'
        env_file:
          - .env
        command: radiusd -X
        networks:
          - backend
    networks:
      backend:
        ipam:
          config:
            - subnet: 10.0.0.0/24

Здесь мы сохраняем в volume ключи сертификата, чтобы при каждом перезапуске сервера, не генерировать их снова.

Пробрасываем порты, необходимые для подключения к серверу, а также для генерации сертификатов через Let's Encrypt.

Перед запуском и сборкой контейнеров, необходимо создать и заполнить `.env` файл, в который помещаем следующее:
      
    VPNHOST=vpn.vpn.com # домен нашего vpn-сервера
    LEEMAIL=admin@admin.com # адрес почты, который будет использован для генерации сертификатов Let's Encrypt
    SPEED_LIMIT=20 # если нужно, то указываем как лимит скорости в mbit
    DNS_SERVERS= # если нужно то указываем собственные DNS сервера
    RADIUS_SERVER= # адрес radius сервера, в нашем случае это будет radius
    RADIUS_SERVER_SECRET= # секретный ключ, с помощью которого проходит авторизация на radius сервере
    REMOTE_SERVER= # в эту переменную вынесли endpoint на который отправлялась статистика из radius сервера, об этом расскажу далее.

Выполняя команду `docker-compose up -d` мы запускаем наш vpn-сервер, а также radius сервер (если он вам нужен).

[Вот так выглядит весь проект в сборке](https://github.com/appbooster/docker-ikev2-vpn-server)

## Сбор статистики с VPN-сервера

Нам ещё было очень интересно сколько пользователей подключено в данный момент к серверу, какой объём трафика потребляется и раздаётся на сервере. Изначально хотели сделать всё максимально просто и забирать статистику через команды ipsec, но столкнулись с тем, что мы можем терять данные из-за того, что пользователь может отключиться или подключиться в период таймаута между командами для сбора статистики. 

Испробовав разные варианты, решили остановиться и разобраться как настроить FreeRadius сервер, который как раз и будет получать данные от ipsec и отправлять данные с статистикой нам.

FreeRadius сервер можно использовать и для авторизации пользователей, но мы остановились только на сборе статистики.
Для включения radius необходимо добавить следующее в конфигурацию ipsec:

# FreeRADIUS сервер для мониторинга подключений к серверу и сбора статистики
    if [[ ! -z "$RADIUS_SERVER" && ! -z "$RADIUS_SERVER_SECRET" ]]; then
    rm /usr/local/etc/strongswan.d/charon/eap-radius.conf
    cat >> /usr/local/etc/strongswan.d/charon/eap-radius.conf <<EOF
    eap-radius {
        accounting = yes # включаем аккаунтинг, ipsec будет отправлять данные о том что пользователь подключился/отключитлся, а так же отправлять данные о объёме используемого трафика
        accounting_close_on_timeout = no
        accounting_interval = 300 # интервал через который radius сервер будет отправлять данные нам.
        close_all_on_timeout = no
        load = yes
        nas_identifier = $VPNHOST

        # Section to specify multiple RADIUS servers.
        servers {
            primary {
                address = $RADIUS_SERVER
                secret = $RADIUS_SERVER_SECRET
                auth_port = 1812   # default
                acct_port = 1813   # default
            }
        }
    }

Чтобы наши данные уходили на наш endpoint, включаем модуль rest. Для этого в файле **/etc/raddb/mods-enabled/rest** настраиваем блок **accounting**, получится что-то вроде:

    accounting {
		uri = "${..connect_uri}/vpn_sessions/%{Acct-Session-Id}-%{Acct-Unique-Session-ID}"
    method = 'post'
    tls = ${..tls}
    body = json
    data = '{ "username": "%{User-Name}", "nas_port": "%{NAS-Port}", "nas_ip_address": "%{NAS-IP-Address}", "framed_ip_address": "%{Framed-IP-Address}", "framed_ipv6_prefix": "%{Framed-IPv6-Prefix}", "nas_identifier": "%{NAS-Identifier}", "airespace_wlan_id": "%{Airespace-Wlan-Id}", "acct_session_id": "%{Acct-Session-Id}", "nas_port_type": "%{NAS-Port-Type}", "cisco_avpair": "%{Cisco-AVPair}", "acct_authentic": "%{Acct-Authentic}", "tunnel_type": "%{Tunnel-Type}", "tunnel_medium_type": "%{Tunnel-Medium-Type}", "tunnel_private_group_id": "%{Tunnel-Private-Group-Id}", "event_timestamp": "%{Event-Timestamp}", "acct_status_type": "%{Acct-Status-Type}", "acct_input_octets": "%{Acct-Input-Octets}", "acct_input_gigawords": "%{Acct-Input-Gigawords}", "acct_output_octets": "%{Acct-Output-Octets}", "acct_output_gigawords": "%{Acct-Output-Gigawords}", "acct_input_packets": "%{Acct-Input-Packets}", "acct_output_packets": "%{Acct-Output-Packets}", "acct_terminate_cause": "%{Acct-Terminate-Cause}", "acct_session_time": "%{Acct-Session-Time}", "acct_delay_time": "%{Acct-Delay-Time}", "calling_station_id": "%{Calling-Station-Id}", "called_station_id": "%{Called-Station-Id}"}'

	 }
   
Здесь мы можем как угодно комбинировать данные и отправлять на наш сервер.

При настройке VPN сервера столкнулись с некоторыми нюансами, вроде таких, что устройства Apple не могут подключить к серверу, если на нём будет самоподписанный сертификат, всё заработало только после того как сертификат начали генерировать через Let's Encrypt.

Что же у нас получилось в итоге?
Методом проб и ошибок мы пришли к варианту который описан в статье, прежде всего мы предерживались принципа "делай проще", не стали изобретать свои велосипеды и воспользовались уже готовыми инструментами типа Docker, FreeRadius, да, скорее всего тут есть место для оптимизации, ужесточения политик безопастности, автоматизации. Наш вариант отлично подойдёт и для личного использования, использования в небольших компаниях, если вам нужно организовать доступ к приватной (закрытой) информации.
