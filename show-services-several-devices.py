from netmiko import ConnectHandler
#automated show specific configurations for list of devices
hosts = ['x', 'x']

for ip in hosts:

    cisco_device = {
        'device_type': 'cisco_ios',
        'host':   ip,
        'username': 'test',
        'password': 'test',
        'port' : 22,          # optional, defaults to 22
        'secret': 'test',     # optional, defaults to ''
    }

    net_connect = ConnectHandler(**cisco_device)

    sh_username = net_connect.send_command('show running-config | i username')
    sh_snmp = net_connect.send_command('show running-config | i snmp')
    sh_logging = net_connect.send_command('show running-config | i logging')
    sh_ntp = net_connect.send_command('show running-config | i ntp')
    sh_tacacs = net_connect.send_command('show running-config | i tacacs')
    sh_aaa = net_connect.send_command('show running-config | i aaa')
    sh_server = net_connect.send_command('show running-config | i server')
    sh_linevty = net_connect.send_command('show running-config | b vty | i access-class')
    sh_acl = net_connect.send_command('show access-list | b ssh')
    print('Information for {} \n'.format(ip))
    print('************usernames***************** \n')
    print(sh_username)
    print('*************snmp**************** \n')
    print(sh_snmp)
    print('**************Syslog************** \n')
    print(sh_logging)
    print('*************NTP config**************** \n')
    print(sh_ntp)
    print('**************TACACS*************** \n')
    print(sh_tacacs)
    print('**************AAA*************** \n')
    print(sh_aaa)
    print('**************Tac-servers*************** \n')
    print(sh_server)
    print('**************LineVTY*************** \n')
    print(sh_linevty)
    print('*************ManagmentACL**************** \n')
    print(sh_acl)
    print('***************************** \n')
    print('***************************** \n')

