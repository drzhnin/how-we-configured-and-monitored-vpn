# Как мы выбирали VPN-протокол и сервер настраивали

## Зачем всё это и для чего?

Я думаю что в IT сфере уже не найти человека который не знал бы, что такое VPN и зачем он нужен.
Но если тезисно объянять зачем нужен VPN современному человеку, то получится примерно следующее:
* Если у вас есть какие-то внутренние (приватные) ресурсы, доступ к которым должен быть ограничен из глобальной сети интернет.
* Если вам необходимо огранизовать защищённое соединение между двумя сетями.
* Если вам нужно получить доступ к ресурсам, которые по тем или иным причинам недоступны из вашей страны (меняется ваше местоположение относительно вашего IP-адреса).

И не совсем очевидный момент, скорость интернет соединения может быть выше через vpn, т.к. ваш провайдер может отправить ваш траффик по более короткому маршруту, а значит более оптимальному маршруту, из-за этого вы и можете получить прирост в скорости. Но это может сработать и в обратную сторону, если вы выберете не очень удачное расположение сервера относительно вас (об этом немного позже).

## Как мы выбирали VPN-протокол

Перед нами стояла задача, поднять VPN-сервер который обеспечит надёжное подключение с минимальной потерей скорости подключения.
Ещё одним условием было, что выбранный VPN-протокол должен без проблем поддерживаться на мобильных устройствах, без установки дополнительного программного обеспечения.
Мы выбрали самые изместные реализации протоколов и отсеяли не подходящие по условиям исходой задачи.
А условия всего два, я напомню:
* Стабильное и надёжное подключение.
* Без установки стороннего программного обеспечения на устройство клиента.

Пробегусь по протоколам и кратко расскажу о них + расскажу причины почему тот или иной протокол нам не подошёл.

### PPTP (Point-To-Point Tunneling Protocol)

Один из самых старейших VPN протоколов, разработанный компанией Microsoft. Из-за солидного возраста протокол поддерживается большинством операционных систем, но в тоже время не может обеспечить стабильное и надёжное соединение. Компания Microsoft советует использовать L2TP или SSTP на замену PPTP.
Этот протокол прост в настройке и не требователем к ресурсам сервера, но проблемы с безапостностью застявляют отказаться от его использования в наших целях.

### L2TP/IPSec

Протокол во многом схож с PPTP, разрабатывался и принимался практически одновременном с ним. Этот протокол более требователен к вычислительным мощностям, часто используется интернет провайдерами, т.к. считается более эффективным для построения виртуальных сетей.
L2TP/IPsec позволяет обеспечить высокую безопасность данных, поддерживается всеми современными операционными системами. Есть одно НО, инкапсулирует передаваемые данные дважды, что делает его менее эффективным и более медленным, чем другие VPN-протоколы.
От этого протокола пришлось отказаться т.к. он более требователен к вычислительным мощностям сервера, а значит велик риск получить стабильное НО медленное соединение, что может огорчить пользователей.

### IKEv2/IPSec

Был разработан Microsoft совместно с Cisco, существуют реализации протокола с открытым исходным кодом (например, OpenIKEv2, Openswan и strongSwan).
Поддерживает Mobility and Multi-homing Protocol (MOBIKE), что обеспечивает устойчивость к смене сетей.
IKEv2 очень хорошо подходит для использования на мобильных устройствах, которые чаще всего склонны к переключению между WiFI и мобильным интернетом.
IKEv2 имеет нативную поддержку в большинстве операционных систем.
Вот этот вариант нам уже больше подходит, т.к. пожжержка Mobility and Multi-homing Protocol будет очень большим плюсом при использовании на мобильных устройствах.

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


