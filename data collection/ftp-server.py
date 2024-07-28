from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

add = "0.0.0.0"
port = 21
user = "anis"
pswd = "2906"
directory = "/home/mini/ftp"

def start_ftp_server():
    authorizer = DummyAuthorizer()
    authorizer.add_user(user, pswd, directory, perm="elradfmw")

    handler = FTPHandler
    handler.authorizer = authorizer
    server = FTPServer((add, port), handler)
    print(f"FTP server running on {add}:{port}")
    server.serve_forever()

if __name__ == "__main__":
    start_ftp_server()

