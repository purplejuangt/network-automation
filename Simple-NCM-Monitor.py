from netmiko import ConnectHandler

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

    output = net_connect.send_command('show running-config')
    print(output)
    f = open('/x/x/x/x {}.txt'.format(cisco_device['host']), 'r')
    readingoldconf = f.read()


    if output != readingoldconf:
        print('Configuration has changed for {}'.format(cisco_device['host']))
    else:
        print('Configuration is still the same for {}'.format(cisco_device['host']))
