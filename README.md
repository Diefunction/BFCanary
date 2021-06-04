# BFCanary

BFCanary is a multiprocessing tool to brute-force x64 canary value, frame pointer, and return address. 

## Requirements
```
apt-get update
apt-get install python3 python3-dev python3-pip git
pip3 install --upgrade git+https://github.com/arthaud/python3-pwntools.git
```

### Example

```python
if __name__ == '__main__':
  BFCanary('127.0.0.1', 1337, b'\x41' * offset, b'Bye')
```

![Example](https://raw.githubusercontent.com/DieFunction/BFCanary/master/img.png)