import re

class Ipv4NetworkCalculator():
    def __init__(self, ip='', prefixo='', mascara='',
                 rede='', broadcast='', numero_ips=''):
        self.ip = ip
        self.prefixo = prefixo
        self.mascara = mascara
        self.rede = rede
        self.broadcast = broadcast
        self.ip = ip
        self.numero_ips = numero_ips


        if self.ip == '':
            raise ValueError("IP NÃO ENVIADO")

        self.ip_tem_prefix()

        if not self.is_ip():
            raise ValueError("IP inválido")

        if not self.prefixo and not self.mascara:
            raise ValueError("O prefixo ou a máscara precisam ser enviados")
        if self.mascara:
            self.mascara_bin = self.ip_decimal_para_binario(ip = self.mascara)
            self.prefixo_da_mascara()
        
        self.set_numero_ips()
        self.set_rede_broadcast()
        self.mascara_do_prefixo()


    def mascara_do_prefixo(self):
        mascara_bin = ''
        for i in range(32):
            if i < int(self.prefixo):
                mascara_bin += '1'
            else:
                mascara_bin += '0'
        mascara_dec = self.ip_binario_para_decimal(mascara_bin)
        self.mascara = mascara_dec


    def set_rede_broadcast(self):
        ip_bin = self.ip_decimal_para_binario(self.ip)
        ip_bin = ip_bin.replace('.', '')
        rede = ''
        broadcast = ''

        for conta, bit in enumerate(ip_bin):
            if conta < int(self.prefixo):
                rede += str(bit)
                broadcast += str(bit)
            else:
                rede += '0'
                broadcast += '1'

        self.rede = self.ip_binario_para_decimal(rede)

        self.broadcast = self.ip_binario_para_decimal(broadcast)


    def ip_binario_para_decimal(self, ip=''):
        novo_ip = str(int(ip[0:8], 2)) + '.'
        novo_ip += str(int(ip[8:16], 2)) + '.'
        novo_ip += str(int(ip[16:24], 2)) + '.'
        novo_ip += str(int(ip[24:32], 2))
        return novo_ip


    def set_numero_ips(self):
        hosts_bits = 32 - int(self.prefixo)
        self.numero_ips = pow(2, hosts_bits)


    def prefixo_da_mascara(self):
        mascara_bin = self.mascara_bin.replace('.', '')
        conta = 0

        for bit in mascara_bin:
            if bit == '1':
                conta += 1
        self.prefixo = conta

    def ip_decimal_para_binario(self, ip=''):
        if not ip:
            ip = self.ip

        bloco_ip = ip.split('.')
        ip_bin = []

        for bloco in bloco_ip:
            binario = bin(int(bloco))
            binario = binario[2:].zfill(8)
            ip_bin.append(binario)

        ip_bin = '.'.join(ip_bin)
        return ip_bin


    def ip_tem_prefix(self):
        ip_prefixo_regexp = re.compile('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0import re

class Ipv4NetworkCalculator():
    def __init__(self, ip='', prefixo='', mascara='',
                 rede='', broadcast='', numero_ips=''):
        self.ip = ip
        self.prefixo = prefixo
        self.mascara = mascara
        self.rede = rede
        self.broadcast = broadcast
        self.ip = ip
        self.numero_ips = numero_ips


        if self.ip == '':
            raise ValueError("IP NÃO ENVIADO")

        self.ip_tem_prefix()

        if not self.is_ip():
            raise ValueError("IP inválido")

        if not self.prefixo and not self.mascara:
            raise ValueError("O prefixo ou a máscara precisam ser enviados")
        if self.mascara:
            self.mascara_bin = self.ip_decimal_para_binario(ip = self.mascara)
            self.prefixo_da_mascara()
        
        self.set_numero_ips()
        self.set_rede_broadcast()
        self.mascara_do_prefixo()


    def mascara_do_prefixo(self):
        mascara_bin = ''
        for i in range(32):
            if i < int(self.prefixo):
                mascara_bin += '1'
            else:
                mascara_bin += '0'
        mascara_dec = self.ip_binario_para_decimal(mascara_bin)
        self.mascara = mascara_dec


    def set_rede_broadcast(self):
        ip_bin = self.ip_decimal_para_binario(self.ip)
        ip_bin = ip_bin.replace('.', '')
        rede = ''
        broadcast = ''

        for conta, bit in enumerate(ip_bin):
            if conta < int(self.prefixo):
                rede += str(bit)
                broadcast += str(bit)
            else:
                rede += '0'
                broadcast += '1'

        self.rede = self.ip_binario_para_decimal(rede)

        self.broadcast = self.ip_binario_para_decimal(broadcast)


    def ip_binario_para_decimal(self, ip=''):
        novo_ip = str(int(ip[0:8], 2)) + '.'
        novo_ip += str(int(ip[8:16], 2)) + '.'
        novo_ip += str(int(ip[16:24], 2)) + '.'
        novo_ip += str(int(ip[24:32], 2))
        return novo_ip


    def set_numero_ips(self):
        hosts_bits = 32 - int(self.prefixo)
        self.numero_ips = pow(2, hosts_bits)


    def prefixo_da_mascara(self):
        mascara_bin = self.mascara_bin.replace('.', '')
        conta = 0

        for bit in mascara_bin:
            if bit == '1':
                conta += 1
        self.prefixo = conta

    def ip_decimal_para_binario(self, ip=''):
        if not ip:
            ip = self.ip

        bloco_ip = ip.split('.')
        ip_bin = []

        for bloco in bloco_ip:
            binario = bin(int(bloco))
            binario = binario[2:].zfill(8)
            ip_bin.append(binario)

        ip_bin = '.'.join(ip_bin)
        return ip_bin


    def ip_tem_prefix(self):
        ip_prefixo_regexp = re.compile('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{1,2}$')

        if not ip_prefixo_regexp.search(self.ip):
            return

        divide_ip = self.ip.split('/')
        self.ip = divide_ip[0]
        self.prefixo = divide_ip[1]

    def is_ip(self):
        ip_regexp = re.compile('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$')

        if ip_regexp.search(self.ip):
            return Trueimport re

class Ipv4NetworkCalculator():
    def __init__(self, ip='', prefixo='', mascara='',
                 rede='', broadcast='', numero_ips=''):
        self.ip = ip
        self.prefixo = prefixo
        self.mascara = mascara
        self.rede = rede
        self.broadcast = broadcast
        self.ip = ip
        self.numero_ips = numero_ips


        if self.ip == '':
            raise ValueError("IP NÃO ENVIADO")

        self.ip_tem_prefix()

        if not self.is_ip():
            raise ValueError("IP inválido")

        if not self.prefixo and not self.mascara:
            raise ValueError("O prefixo ou a máscara precisam ser enviados")
        if self.mascara:
            self.mascara_bin = self.ip_decimal_para_binario(ip = self.mascara)
            self.prefixo_da_mascara()
        
        self.set_numero_ips()
        self.set_rede_broadcast()
        self.mascara_do_prefixo()


    def mascara_do_prefixo(self):
        mascara_bin = ''
        for i in range(32):
            if i < int(self.prefixo):
                mascara_bin += '1'
            else:
                mascara_bin += '0'
        mascara_dec = self.ip_binario_para_decimal(mascara_bin)
        self.mascara = mascara_dec


    def set_rede_broadcast(self):
        ip_bin = self.ip_decimal_para_binario(self.ip)
        ip_bin = ip_bin.replace('.', '')
        rede = ''
        broadcast = ''

        for conta, bit in enumerate(ip_bin):
            if conta < int(self.prefixo):
                rede += str(bit)
                broadcast += str(bit)
            else:
                rede += '0'
                broadcast += '1'

        self.rede = self.ip_binario_para_decimal(rede)

        self.broadcast = self.ip_binario_para_decimal(broadcast)


    def ip_binario_para_decimal(self, ip=''):
        novo_ip = str(int(ip[0:8], 2)) + '.'
        novo_ip += str(int(ip[8:16], 2)) + '.'
        novo_ip += str(int(ip[16:24], 2)) + '.'
        novo_ip += str(int(ip[24:32], 2))
        return novo_ip


    def set_numero_ips(self):
        hosts_bits = 32 - int(self.prefixo)
        self.numero_ips = pow(2, hosts_bits)


    def prefixo_da_mascara(self):
        mascara_bin = self.mascara_bin.replace('.', '')
        conta = 0

        for bit in mascara_bin:
            if bit == '1':
                conta += 1
        self.prefixo = conta

    def ip_decimal_para_binario(self, ip=''):
        if not ip:
            ip = self.ip

        bloco_ip = ip.split('.')
        ip_bin = []

        for bloco in bloco_ip:
            binario = bin(int(bloco))
            binario = binario[2:].zfill(8)
            ip_bin.append(binario)

        ip_bin = '.'.join(ip_bin)
        return ip_bin


    def ip_tem_prefix(self):
        ip_prefixo_regexp = re.compile('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{1,2}$')

        if not ip_prefixo_regexp.search(self.ip):
            return

        divide_ip = self.ip.split('/')
        self.ip = divide_ip[0]
        self.prefixo = divide_ip[1]

    def is_ip(self):
        ip_regexp = re.compile('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$')

        if ip_regexp.search(self.ip):
            return Trueimport re

class Ipv4NetworkCalculator():
    def __init__(self, ip='', prefixo='', mascara='',
                 rede='', broadcast='', numero_ips=''):
        self.ip = ip
        self.prefixo = prefixo
        self.mascara = mascara
        self.rede = rede
        self.broadcast = broadcast
        self.ip = ip
        self.numero_ips = numero_ips


        if self.ip == '':
            raise ValueError("IP NÃO ENVIADO")

        self.ip_tem_prefix()

        if not self.is_ip():
            raise ValueError("IP inválido")

        if not self.prefixo and not self.mascara:
            raise ValueError("O prefixo ou a máscara precisam ser enviados")
        if self.mascara:
            self.mascara_bin = self.ip_decimal_para_binario(ip = self.mascara)
            self.prefixo_da_mascara()
        
        self.set_numero_ips()
        self.set_rede_broadcast()
        self.mascara_do_prefixo()


    def mascara_do_prefixo(self):
        mascara_bin = ''
        for i in range(32):
            if i < int(self.prefixo):
                mascara_bin += '1'
            else:
                mascara_bin += '0'
        mascara_dec = self.ip_binario_para_decimal(mascara_bin)
        self.mascara = mascara_dec


    def set_rede_broadcast(self):
        ip_bin = self.ip_decimal_para_binario(self.ip)
        ip_bin = ip_bin.replace('.', '')
        rede = ''
        broadcast = ''

        for conta, bit in enumerate(ip_bin):
            if conta < int(self.prefixo):
                rede += str(bit)
                broadcast += str(bit)
            else:
                rede += '0'
                broadcast += '1'

        self.rede = self.ip_binario_para_decimal(rede)

        self.broadcast = self.ip_binario_para_decimal(broadcast)


    def ip_binario_para_decimal(self, ip=''):
        novo_ip = str(int(ip[0:8], 2)) + '.'
        novo_ip += str(int(ip[8:16], 2)) + '.'
        novo_ip += str(int(ip[16:24], 2)) + '.'
        novo_ip += str(int(ip[24:32], 2))
        return novo_ip


    def set_numero_ips(self):
        hosts_bits = 32 - int(self.prefixo)
        self.numero_ips = pow(2, hosts_bits)


    def prefixo_da_mascara(self):
        mascara_bin = self.mascara_bin.replace('.', '')
        conta = 0

        for bit in mascara_bin:
            if bit == '1':
                conta += 1
        self.prefixo = conta

    def ip_decimal_para_binario(self, ip=''):
        if not ip:
            ip = self.ip

        bloco_ip = ip.split('.')
        ip_bin = []

        for bloco in bloco_ip:
            binario = bin(int(bloco))
            binario = binario[2:].zfill(8)
            ip_bin.append(binario)

        ip_bin = '.'.join(ip_bin)
        return ip_bin


    def ip_tem_prefix(self):
        ip_prefixo_regexp = re.compile('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{1,2}$')

        if not ip_prefixo_regexp.search(self.ip):
            return

        divide_ip = self.ip.split('/')
        self.ip = divide_ip[0]
        self.prefixo = divide_ip[1]

    def is_ip(self):
        ip_regexp = re.compile('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$')

        if ip_regexp.search(self.ip):
            return Trueimport re

class Ipv4NetworkCalculator():
    def __init__(self, ip='', prefixo='', mascara='',
                 rede='', broadcast='', numero_ips=''):
        self.ip = ip
        self.prefixo = prefixo
        self.mascara = mascara
        self.rede = rede
        self.broadcast = broadcast
        self.ip = ip
        self.numero_ips = numero_ips


        if self.ip == '':
            raise ValueError("IP NÃO ENVIADO")

        self.ip_tem_prefix()

        if not self.is_ip():
            raise ValueError("IP inválido")

        if not self.prefixo and not self.mascara:
            raise ValueError("O prefixo ou a máscara precisam ser enviados")
        if self.mascara:
            self.mascara_bin = self.ip_decimal_para_binario(ip = self.mascara)
            self.prefixo_da_mascara()
        
        self.set_numero_ips()
        self.set_rede_broadcast()
        self.mascara_do_prefixo()


    def mascara_do_prefixo(self):
        mascara_bin = ''
        for i in range(32):
            if i < int(self.prefixo):
                mascara_bin += '1'
            else:
                mascara_bin += '0'
        mascara_dec = self.ip_binario_para_decimal(mascara_bin)
        self.mascara = mascara_dec


    def set_rede_broadcast(self):
        ip_bin = self.ip_decimal_para_binario(self.ip)
        ip_bin = ip_bin.replace('.', '')
        rede = ''
        broadcast = ''

        for conta, bit in enumerate(ip_bin):
            if conta < int(self.prefixo):
                rede += str(bit)
                broadcast += str(bit)
            else:
                rede += '0'
                broadcast += '1'

        self.rede = self.ip_binario_para_decimal(rede)

        self.broadcast = self.ip_binario_para_decimal(broadcast)


    def ip_binario_para_decimal(self, ip=''):
        novo_ip = str(int(ip[0:8], 2)) + '.'
        novo_ip += str(int(ip[8:16], 2)) + '.'
        novo_ip += str(int(ip[16:24], 2)) + '.'
        novo_ip += str(int(ip[24:32], 2))
        return novo_ip


    def set_numero_ips(self):
        hosts_bits = 32 - int(self.prefixo)
        self.numero_ips = pow(2, hosts_bits)


    def prefixo_da_mascara(self):
        mascara_bin = self.mascara_bin.replace('.', '')
        conta = 0

        for bit in mascara_bin:
            if bit == '1':
                conta += 1
        self.prefixo = conta

    def ip_decimal_para_binario(self, ip=''):
        if not ip:
            ip = self.ip

        bloco_ip = ip.split('.')
        ip_bin = []

        for bloco in bloco_ip:
            binario = bin(int(bloco))
            binario = binario[2:].zfill(8)
            ip_bin.append(binario)

        ip_bin = '.'.join(ip_bin)
        return ip_bin


    def ip_tem_prefix(self):
        ip_prefixo_regexp = re.compile('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{1,2}$')

        if not ip_prefixo_regexp.search(self.ip):
            return

        divide_ip = self.ip.split('/')
        self.ip = divide_ip[0]
        self.prefixo = divide_ip[1]

    def is_ip(self):
        ip_regexp = re.compile('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$')

        if ip_regexp.search(self.ip):
            return Trueimport re

class Ipv4NetworkCalculator():
    def __init__(self, ip='', prefixo='', mascara='',
                 rede='', broadcast='', numero_ips=''):
        self.ip = ip
        self.prefixo = prefixo
        self.mascara = mascara
        self.rede = rede
        self.broadcast = broadcast
        self.ip = ip
        self.numero_ips = numero_ips


        if self.ip == '':
            raise ValueError("IP NÃO ENVIADO")

        self.ip_tem_prefix()

        if not self.is_ip():
            raise ValueError("IP inválido")

        if not self.prefixo and not self.mascara:
            raise ValueError("O prefixo ou a máscara precisam ser enviados")
        if self.mascara:
            self.mascara_bin = self.ip_decimal_para_binario(ip = self.mascara)
            self.prefixo_da_mascara()
        
        self.set_numero_ips()
        self.set_rede_broadcast()
        self.mascara_do_prefixo()


    def mascara_do_prefixo(self):
        mascara_bin = ''
        for i in range(32):
            if i < int(self.prefixo):
                mascara_bin += '1'
            else:
                mascara_bin += '0'
        mascara_dec = self.ip_binario_para_decimal(mascara_bin)
        self.mascara = mascara_dec


    def set_rede_broadcast(self):
        ip_bin = self.ip_decimal_para_binario(self.ip)
        ip_bin = ip_bin.replace('.', '')
        rede = ''
        broadcast = ''

        for conta, bit in enumerate(ip_bin):
            if conta < int(self.prefixo):
                rede += str(bit)
                broadcast += str(bit)
            else:
                rede += '0'
                broadcast += '1'

        self.rede = self.ip_binario_para_decimal(rede)

        self.broadcast = self.ip_binario_para_decimal(broadcast)


    def ip_binario_para_decimal(self, ip=''):
        novo_ip = str(int(ip[0:8], 2)) + '.'
        novo_ip += str(int(ip[8:16], 2)) + '.'
        novo_ip += str(int(ip[16:24], 2)) + '.'
        novo_ip += str(int(ip[24:32], 2))
        return novo_ip


    def set_numero_ips(self):
        hosts_bits = 32 - int(self.prefixo)
        self.numero_ips = pow(2, hosts_bits)


    def prefixo_da_mascara(self):
        mascara_bin = self.mascara_bin.replace('.', '')
        conta = 0

        for bit in mascara_bin:
            if bit == '1':
                conta += 1
        self.prefixo = conta

    def ip_decimal_para_binario(self, ip=''):
        if not ip:
            ip = self.ip

        bloco_ip = ip.split('.')
        ip_bin = []

        for bloco in bloco_ip:
            binario = bin(int(bloco))
            binario = binario[2:].zfill(8)
            ip_bin.append(binario)

        ip_bin = '.'.join(ip_bin)
        return ip_bin


    def ip_tem_prefix(self):
        ip_prefixo_regexp = re.compile('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{1,2}$')

        if not ip_prefixo_regexp.search(self.ip):
            return

        divide_ip = self.ip.split('/')
        self.ip = divide_ip[0]
        self.prefixo = divide_ip[1]

    def is_ip(self):
        ip_regexp = re.compile('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$')

        if ip_regexp.search(self.ip):
            return Trueimport re

class Ipv4NetworkCalculator():
    def __init__(self, ip='', prefixo='', mascara='',
                 rede='', broadcast='', numero_ips=''):
        self.ip = ip
        self.prefixo = prefixo
        self.mascara = mascara
        self.rede = rede
        self.broadcast = broadcast
        self.ip = ip
        self.numero_ips = numero_ips


        if self.ip == '':
            raise ValueError("IP NÃO ENVIADO")

        self.ip_tem_prefix()

        if not self.is_ip():
            raise ValueError("IP inválido")

        if not self.prefixo and not self.mascara:
            raise ValueError("O prefixo ou a máscara precisam ser enviados")
        if self.mascara:
            self.mascara_bin = self.ip_decimal_para_binario(ip = self.mascara)
            self.prefixo_da_mascara()
        
        self.set_numero_ips()
        self.set_rede_broadcast()
        self.mascara_do_prefixo()


    def mascara_do_prefixo(self):
        mascara_bin = ''
        for i in range(32):
            if i < int(self.prefixo):
                mascara_bin += '1'
            else:
                mascara_bin += '0'
        mascara_dec = self.ip_binario_para_decimal(mascara_bin)
        self.mascara = mascara_dec


    def set_rede_broadcast(self):
        ip_bin = self.ip_decimal_para_binario(self.ip)
        ip_bin = ip_bin.replace('.', '')
        rede = ''
        broadcast = ''

        for conta, bit in enumerate(ip_bin):
            if conta < int(self.prefixo):
                rede += str(bit)
                broadcast += str(bit)
            else:
                rede += '0'
                broadcast += '1'

        self.rede = self.ip_binario_para_decimal(rede)

        self.broadcast = self.ip_binario_para_decimal(broadcast)


    def ip_binario_para_decimal(self, ip=''):
        novo_ip = str(int(ip[0:8], 2)) + '.'
        novo_ip += str(int(ip[8:16], 2)) + '.'
        novo_ip += str(int(ip[16:24], 2)) + '.'
        novo_ip += str(int(ip[24:32], 2))
        return novo_ip


    def set_numero_ips(self):
        hosts_bits = 32 - int(self.prefixo)
        self.numero_ips = pow(2, hosts_bits)


    def prefixo_da_mascara(self):
        mascara_bin = self.mascara_bin.replace('.', '')
        conta = 0

        for bit in mascara_bin:
            if bit == '1':
                conta += 1
        self.prefixo = conta

    def ip_decimal_para_binario(self, ip=''):
        if not ip:
            ip = self.ip

        bloco_ip = ip.split('.')
        ip_bin = []

        for bloco in bloco_ip:
            binario = bin(int(bloco))
            binario = binario[2:].zfill(8)
            ip_bin.append(binario)

        ip_bin = '.'.join(ip_bin)
        return ip_bin


    def ip_tem_prefix(self):
        ip_prefixo_regexp = re.compile('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{1,2}$')

        if not ip_prefixo_regexp.search(self.ip):
            return

        divide_ip = self.ip.split('/')
        self.ip = divide_ip[0]
        self.prefixo = divide_ip[1]

    def is_ip(self):
        ip_regexp = re.compile('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$')

        if ip_regexp.search(self.ip):import re

class Ipv4NetworkCalculator():
    def __init__(self, ip='', prefixo='', mascara='',
                 rede='', broadcast='', numero_ips=''):
        self.ip = ip
        self.prefixo = prefixo
        self.mascara = mascara
        self.rede = rede
        self.broadcast = broadcast
        self.ip = ip
        self.numero_ips = numero_ips


        if self.ip == '':
            raise ValueError("IP NÃO ENVIADO")

        self.ip_tem_prefix()

        if not self.is_ip():
            raise ValueError("IP inválido")

        if not self.prefixo and not self.mascara:
            raise ValueError("O prefixo ou a máscara precisam ser enviados")
        if self.mascara:
            self.mascara_bin = self.ip_decimal_para_binario(ip = self.mascara)
            self.prefixo_da_mascara()
        
        self.set_numero_ips()
        self.set_rede_broadcast()
        self.mascara_do_prefixo()


    def mascara_do_prefixo(self):
        mascara_bin = ''
        for i in range(32):
            if i < int(self.prefixo):
                mascara_bin += '1'
            else:
                mascara_bin += '0'
        mascara_dec = self.ip_binario_para_decimal(mascara_bin)
        self.mascara = mascara_dec


    def set_rede_broadcast(self):
        ip_bin = self.ip_decimal_para_binario(self.ip)
        ip_bin = ip_bin.replace('.', '')
        rede = ''
        broadcast = ''

        for conta, bit in enumerate(ip_bin):
            if conta < int(self.prefixo):
                rede += str(bit)
                broadcast += str(bit)
            else:
                rede += '0'
                broadcast += '1'

        self.rede = self.ip_binario_para_decimal(rede)

        self.broadcast = self.ip_binario_para_decimal(broadcast)


    def ip_binario_para_decimal(self, ip=''):
        novo_ip = str(int(ip[0:8], 2)) + '.'
        novo_ip += str(int(ip[8:16], 2)) + '.'
        novo_ip += str(int(ip[16:24], 2)) + '.'
        novo_ip += str(int(ip[24:32], 2))
        return novo_ip


    def set_numero_ips(self):
        hosts_bits = 32 - int(self.prefixo)
        self.numero_ips = pow(2, hosts_bits)


    def prefixo_da_mascara(self):
        mascara_bin = self.mascara_bin.replace('.', '')
        conta = 0

        for bit in mascara_bin:
            if bit == '1':
                conta += 1
        self.prefixo = conta

    def ip_decimal_para_binario(self, ip=''):
        if not ip:
            ip = self.ip

        bloco_ip = ip.split('.')
        ip_bin = []

        for bloco in bloco_ip:
            binario = bin(int(bloco))
            binario = binario[2:].zfill(8)
            ip_bin.append(binario)

        ip_bin = '.'.join(ip_bin)
        return ip_bin


    def ip_tem_prefix(self):
        ip_prefixo_regexp = re.compile('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{1,2}$')

        if not ip_prefixo_regexp.search(self.ip):
            return

        divide_ip = self.ip.split('/')
        self.ip = divide_ip[0]
        self.prefixo = divide_ip[1]

    def is_ip(self):
        ip_regexp = re.compile('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$')

        if ip_regexp.search(self.ip):import re

class Ipv4NetworkCalculator():
    def __init__(self, ip='', prefixo='', mascara='',
                 rede='', broadcast='', numero_ips=''):
        self.ip = ip
        self.prefixo = prefixo
        self.mascara = mascara
        self.rede = rede
        self.broadcast = broadcast
        self.ip = ip
        self.numero_ips = numero_ips


        if self.ip == '':
            raise ValueError("IP NÃO ENVIADO")

        self.ip_tem_prefix()

        if not self.is_ip():
            raise ValueError("IP inválido")

        if not self.prefixo and not self.mascara:
            raise ValueError("O prefixo ou a máscara precisam ser enviados")
        if self.mascara:
            self.mascara_bin = self.ip_decimal_para_binario(ip = self.mascara)
            self.prefixo_da_mascara()
        
        self.set_numero_ips()
        self.set_rede_broadcast()
        self.mascara_do_prefixo()


    def mascara_do_prefixo(self):
        mascara_bin = ''
        for i in range(32):
            if i < int(self.prefixo):
                mascara_bin += '1'
            else:
                mascara_bin += '0'
        mascara_dec = self.ip_binario_para_decimal(mascara_bin)
        self.mascara = mascara_dec


    def set_rede_broadcast(self):
        ip_bin = self.ip_decimal_para_binario(self.ip)
        ip_bin = ip_bin.replace('.', '')
        rede = ''
        broadcast = ''

        for conta, bit in enumerate(ip_bin):
            if conta < int(self.prefixo):
                rede += str(bit)
                broadcast += str(bit)
            else:
                rede += '0'
                broadcast += '1'

        self.rede = self.ip_binario_para_decimal(rede)

        self.broadcast = self.ip_binario_para_decimal(broadcast)


    def ip_binario_para_decimal(self, ip=''):
        novo_ip = str(int(ip[0:8], 2)) + '.'
        novo_ip += str(int(ip[8:16], 2)) + '.'
        novo_ip += str(int(ip[16:24], 2)) + '.'
        novo_ip += str(int(ip[24:32], 2))
        return novo_ip


    def set_numero_ips(self):
        hosts_bits = 32 - int(self.prefixo)
        self.numero_ips = pow(2, hosts_bits)


    def prefixo_da_mascara(self):
        mascara_bin = self.mascara_bin.replace('.', '')
        conta = 0

        for bit in mascara_bin:
            if bit == '1':
                conta += 1
        self.prefixo = conta

    def ip_decimal_para_binario(self, ip=''):
        if not ip:
            ip = self.ip

        bloco_ip = ip.split('.')
        ip_bin = []

        for bloco in bloco_ip:
            binario = bin(int(bloco))
            binario = binario[2:].zfill(8)
            ip_bin.append(binario)

        ip_bin = '.'.join(ip_bin)
        return ip_bin


    def ip_tem_prefix(self):
        ip_prefixo_regexp = re.compile('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{1,2}$')

        if not ip_prefixo_regexp.search(self.ip):
            return

        divide_ip = self.ip.split('/')
        self.ip = divide_ip[0]
        self.prefixo = divide_ip[1]

    def is_ip(self):
        ip_regexp = re.compile('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$')

        if ip_regexp.search(self.ip):import re

class Ipv4NetworkCalculator():
    def __init__(self, ip='', prefixo='', mascara='',
                 rede='', broadcast='', numero_ips=''):
        self.ip = ip
        self.prefixo = prefixo
        self.mascara = mascara
        self.rede = rede
        self.broadcast = broadcast
        self.ip = ip
        self.numero_ips = numero_ips


        if self.ip == '':
            raise ValueError("IP NÃO ENVIADO")

        self.ip_tem_prefix()

        if not self.is_ip():
            raise ValueError("IP inválido")

        if not self.prefixo and not self.mascara:
            raise ValueError("O prefixo ou a máscara precisam ser enviados")
        if self.mascara:
            self.mascara_bin = self.ip_decimal_para_binario(ip = self.mascara)
            self.prefixo_da_mascara()
        
        self.set_numero_ips()
        self.set_rede_broadcast()
        self.mascara_do_prefixo()


    def mascara_do_prefixo(self):
        mascara_bin = ''
        for i in range(32):
            if i < int(self.prefixo):
                mascara_bin += '1'
            else:
                mascara_bin += '0'
        mascara_dec = self.ip_binario_para_decimal(mascara_bin)
        self.mascara = mascara_dec


    def set_rede_broadcast(self):
        ip_bin = self.ip_decimal_para_binario(self.ip)
        ip_bin = ip_bin.replace('.', '')
        rede = ''
        broadcast = ''

        for conta, bit in enumerate(ip_bin):
            if conta < int(self.prefixo):
                rede += str(bit)
                broadcast += str(bit)
            else:
                rede += '0'
                broadcast += '1'

        self.rede = self.ip_binario_para_decimal(rede)

        self.broadcast = self.ip_binario_para_decimal(broadcast)


    def ip_binario_para_decimal(self, ip=''):
        novo_ip = str(int(ip[0:8], 2)) + '.'
        novo_ip += str(int(ip[8:16], 2)) + '.'
        novo_ip += str(int(ip[16:24], 2)) + '.'
        novo_ip += str(int(ip[24:32], 2))
        return novo_ip


    def set_numero_ips(self):
        hosts_bits = 32 - int(self.prefixo)
        self.numero_ips = pow(2, hosts_bits)


    def prefixo_da_mascara(self):
        mascara_bin = self.mascara_bin.replace('.', '')
        conta = 0

        for bit in mascara_bin:
            if bit == '1':
                conta += 1
        self.prefixo = conta

    def ip_decimal_para_binario(self, ip=''):
        if not ip:
            ip = self.ip

        bloco_ip = ip.split('.')
        ip_bin = []

        for bloco in bloco_ip:
            binario = bin(int(bloco))
            binario = binario[2:].zfill(8)
            ip_bin.append(binario)

        ip_bin = '.'.join(ip_bin)
        return ip_bin


    def ip_tem_prefix(self):
        ip_prefixo_regexp = re.compile('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{1,2}$')

        if not ip_prefixo_regexp.search(self.ip):
            return

        divide_ip = self.ip.split('/')
        self.ip = divide_ip[0]
        self.prefixo = divide_ip[1]

    def is_ip(self):
        ip_regexp = re.compile('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$')

        if ip_regexp.search(self.ip):
            return True
        return False

    def get_all(self):
        return {
            'ip':self.ip,
            'prefixo':self.prefixo,
            'mascara':self.mascara,
            'rede':self.rede,
            'broadcast':self.broadcast,
            'numero_ips':self.numero_ips
        }


if __name__ == '__main__':
    rodar = 1
    while (rodar == 1):
        print('Calculo dos dados da rede TCP/IPv4')
        ip = input('Valor do IP: ')
        mascara = input('Valor da máscara, pode deixar em branco se a mesma já foi inserida anteriormente: ')
        ipv4 = Ipv4NetworkCalculator(ip=ip, mascara=mascara)

        print(ipv4.get_all())
        rodar = int(input('Deseja calcular novamente? 1 para sim   '))
            return True
        return False

    def get_all(self):
        return {
            'ip':self.ip,
            'prefixo':self.prefixo,
            'mascara':self.mascara,
            'rede':self.rede,
            'broadcast':self.broadcast,
            'numero_ips':self.numero_ips
        }


if __name__ == '__main__':
    rodar = 1
    while (rodar == 1):
        print('Calculo dos dados da rede TCP/IPv4')
        ip = input('Valor do IP: ')
        mascara = input('Valor da máscara, pode deixar em branco se a mesma já foi inserida anteriormente: ')
        ipv4 = Ipv4NetworkCalculator(ip=ip, mascara=mascara)

        print(ipv4.get_all())
        rodar = int(input('Deseja calcular novamente? 1 para sim   '))
            return True
        return False

    def get_all(self):
        return {
            'ip':self.ip,
            'prefixo':self.prefixo,
            'mascara':self.mascara,
            'rede':self.rede,
            'broadcast':self.broadcast,
            'numero_ips':self.numero_ips
        }


if __name__ == '__main__':
    rodar = 1
    while (rodar == 1):
        print('Calculo dos dados da rede TCP/IPv4')
        ip = input('Valor do IP: ')
        mascara = input('Valor da máscara, pode deixar em branco se a mesma já foi inserida anteriormente: ')
        ipv4 = Ipv4NetworkCalculator(ip=ip, mascara=mascara)

        print(ipv4.get_all())
        rodar = int(input('Deseja calcular novamente? 1 para sim   '))
            return True
        return False

    def get_all(self):
        return {
            'ip':self.ip,
            'prefixo':self.prefixo,
            'mascara':self.mascara,
            'rede':self.rede,
            'broadcast':self.broadcast,
            'numero_ips':self.numero_ips
        }


if __name__ == '__main__':
    rodar = 1
    while (rodar == 1):
        print('Calculo dos dados da rede TCP/IPv4')
        ip = input('Valor do IP: ')
        mascara = input('Valor da máscara, pode deixar em branco se a mesma já foi inserida anteriormente: ')
        ipv4 = Ipv4NetworkCalculator(ip=ip, mascara=mascara)

        print(ipv4.get_all())
        rodar = int(input('Deseja calcular novamente? 1 para sim   '))
        return False

    def get_all(self):
        return {
            'ip':self.ip,
            'prefixo':self.prefixo,
            'mascara':self.mascara,
            'rede':self.rede,
            'broadcast':self.broadcast,
            'numero_ips':self.numero_ips
        }


if __name__ == '__main__':
    rodar = 1
    while (rodar == 1):
        print('Calculo dos dados da rede TCP/IPv4')
        ip = input('Valor do IP: ')
        mascara = input('Valor da máscara, pode deixar em branco se a mesma já foi inserida anteriormente: ')
        ipv4 = Ipv4NetworkCalculator(ip=ip, mascara=mascara)

        print(ipv4.get_all())
        rodar = int(input('Deseja calcular novamente? 1 para sim   '))
        return False

    def get_all(self):
        return {
            'ip':self.ip,
            'prefixo':self.prefixo,
            'mascara':self.mascara,
            'rede':self.rede,
            'broadcast':self.broadcast,
            'numero_ips':self.numero_ips
        }


if __name__ == '__main__':
    rodar = 1
    while (rodar == 1):
        print('Calculo dos dados da rede TCP/IPv4')
        ip = input('Valor do IP: ')
        mascara = input('Valor da máscara, pode deixar em branco se a mesma já foi inserida anteriormente: ')
        ipv4 = Ipv4NetworkCalculator(ip=ip, mascara=mascara)

        print(ipv4.get_all())
        rodar = int(input('Deseja calcular novamente? 1 para sim   '))
        return False

    def get_all(self):
        return {
            'ip':self.ip,
            'prefixo':self.prefixo,
            'mascara':self.mascara,
            'rede':self.rede,
            'broadcast':self.broadcast,
            'numero_ips':self.numero_ips
        }


if __name__ == '__main__':
    rodar = 1
    while (rodar == 1):
        print('Calculo dos dados da rede TCP/IPv4')
        ip = input('Valor do IP: ')
        mascara = input('Valor da máscara, pode deixar em branco se a mesma já foi inserida anteriormente: ')
        ipv4 = Ipv4NetworkCalculator(ip=ip, mascara=mascara)

        print(ipv4.get_all())
        rodar = int(input('Deseja calcular novamente? 1 para sim   '))
        return False

    def get_all(self):
        return {
            'ip':self.ip,
            'prefixo':self.prefixo,
            'mascara':self.mascara,
            'rede':self.rede,
            'broadcast':self.broadcast,
            'numero_ips':self.numero_ips
        }


if __name__ == '__main__':
    rodar = 1
    while (rodar == 1):
        print('Calculo dos dados da rede TCP/IPv4')
        ip = input('Valor do IP: ')
        mascara = input('Valor da máscara, pode deixar em branco se a mesma já foi inserida anteriormente: ')
        ipv4 = Ipv4NetworkCalculator(ip=ip, mascara=mascara)

        print(ipv4.get_all())
        rodar = int(input('Deseja calcular novamente? 1 para sim   '))
        return False

    def get_all(self):
        return {
            'ip':self.ip,
            'prefixo':self.prefixo,
            'mascara':self.mascara,
            'rede':self.rede,
            'broadcast':self.broadcast,
            'numero_ips':self.numero_ips
        }


if __name__ == '__main__':
    rodar = 1
    while (rodar == 1):
        print('Calculo dos dados da rede TCP/IPv4')
        ip = input('Valor do IP: ')
        mascara = input('Valor da máscara, pode deixar em branco se a mesma já foi inserida anteriormente: ')
        ipv4 = Ipv4NetworkCalculator(ip=ip, mascara=mascara)

        print(ipv4.get_all())
        rodar = int(input('Deseja calcular novamente? 1 para sim   '))-9]{1,3}/[0-9]{1,2}$')

        if not ip_prefixo_regexp.search(self.ip):
            return

        divide_ip = self.ip.split('/')
        self.ip = divide_ip[0]
        self.prefixo = divide_ip[1]

    def is_ip(self):
        ip_regexp = re.compile('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$')

        if ip_regexp.search(self.ip):
            return True
        return False

    def get_all(self):
        return {
            'ip':self.ip,
            'prefixo':self.prefixo,
            'mascara':self.mascara,
            'rede':self.rede,
            'broadcast':self.broadcast,
            'numero_ips':self.numero_ips
        }


if __name__ == '__main__':
    rodar = 1
    while (rodar == 1):
        print('Calculo dos dados da rede TCP/IPv4')
        ip = input('Valor do IP: ')
        mascara = input('Valor da máscara, pode deixar em branco se a mesma já foi inserida anteriormente: ')
        ipv4 = Ipv4NetworkCalculator(ip=ip, mascara=mascara)

        print(ipv4.get_all())
        rodar = int(input('Deseja calcular novamente? 1 para sim   '))
