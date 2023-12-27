# PySSH3

Translation of [SSH3](https://github.com/francoismichel/ssh3/tree/c39bb79cdce479f6095ab154a32a168e14d73b57) project (from commit `c39bb79cdce479f6095ab154a32a168e14d73b57`) to Python 3 library. Check the original project for more information ! 

## Installation

### Python 3.6 (TODO)

TODO

### Requirements

```bash
make env; make install;
``` 

## Usage

### PySSH3 server

```bash
./ssh3_env/bin/activate && python3 py-ssh3/server_cli.py --help
./ssh3_env/bin/activate && python3 py-ssh3/server_cli.py --generateSelfSignedCert --enablePasswordLogin --bind "127.0.0.1:4443" --urlPath "/my-secret-path" --verbose --insecure
```

#### Authorized keys and authorized identities 
TODO

### PySSH3 client
```bash
./ssh3_env/bin/activate && python3 py-ssh3/client_cli.py --help
./ssh3_env/bin/activate && python3 py-ssh3/client_cli.py --url "127.0.0.1:4443/my-secret-path?user=elniak" --verbose --usePassword
./ssh3_env/bin/activate && python3 py-ssh3/client_cli.py --url "127.0.0.1:4443/my-secret-path?user=elniak" --verbose --privkey ~/.ssh/id_rsa --insecure
```

#### Private-key authentication
TODO
#### Agent-based private key authentication
TODO
#### Password authentication
TODO
#### Config-based session establishment
TODO
#### OpenID Connect authentication (TODO)
TODO

## TODO
- [ ] Add tests
- [ ] Add documentation
- [ ] Add examples
- [ ] Add more features
- [ ] Add threading support
- [ ] Inspire more from [paramiko]
- [ ] Secure version