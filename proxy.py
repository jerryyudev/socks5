import socket
import threading
import logging
from concurrent.futures import ThreadPoolExecutor

# 配置日誌格式和等級
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

def forward(src, dst):
    """
    轉發數據：從 src 接收數據後發送到 dst
    """
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except ConnectionResetError as e:
        if e.winerror == 10054:
            logging.warning("Client forcibly closed connection (10054).")
        else:
            logging.exception("ConnectionResetError: %s", e)
    except OSError as e:
        if e.winerror == 10053:
            logging.warning("Connection aborted (10053) - possibly client closed.")
        else:
            logging.exception("OSError: %s", e)
    except socket.timeout:
        logging.warning("Socket timeout during data forwarding.")
    except Exception as e:
        logging.exception("Unexpected error in forward function: %s", e)
    finally:
        try:
            src.shutdown(socket.SHUT_RD)
        except Exception as e:
            logging.debug("Error shutting down source socket: %s", e)
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception as e:
            logging.debug("Error shutting down destination socket: %s", e)

class Socks5Server:
    def __init__(self, host='0.0.0.0', port=2454, timeout=60, max_workers=100):
        self.host = host
        self.port = port
        self.timeout = timeout  # socket 超時秒數
        self.server_socket = None
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.stop_event = threading.Event()  # 用於控制服務器停止

    def handle_client(self, client_socket, addr):
        """
        處理每個客戶端的 SOCKS5 握手及連接轉發
        """
        logging.info("Handling client from %s:%s", addr[0], addr[1])
        client_socket.settimeout(self.timeout)
        remote = None
        try:
            # 讀取 SOCKS5 協議版本
            ver = client_socket.recv(1)
            if ver != b'\x05':
                logging.warning("Unsupported SOCKS version from %s", addr)
                client_socket.close()
                return

            # 讀取認證方法數量及方法列表（此處不進行認證，只支持無認證方式）
            nmethods = client_socket.recv(1)
            if not nmethods:
                logging.warning("No authentication methods received from %s", addr)
                client_socket.close()
                return
            nmethods = nmethods[0] if isinstance(nmethods, bytes) else ord(nmethods)
            methods = client_socket.recv(nmethods)
            logging.debug("Authentication methods from %s: %s", addr, methods)
            
            # 回覆：不需要認證
            client_socket.sendall(b'\x05\x00')
            
            # 讀取客戶端請求：版本、命令、保留位及地址類型
            header = client_socket.recv(4)
            if len(header) < 4:
                logging.warning("Incomplete header from %s", addr)
                client_socket.close()
                return
            ver, cmd, rsv, atyp = header
            if cmd != 1:
                logging.warning("Unsupported CMD %s from %s", cmd, addr)
                client_socket.close()
                return
            
            # 根據地址類型解析目標地址
            if atyp == 1:  # IPv4
                addr_ip = socket.inet_ntoa(client_socket.recv(4))
            elif atyp == 3:  # 域名
                domain_len = client_socket.recv(1)[0]
                addr_ip = client_socket.recv(domain_len).decode()
            elif atyp == 4:  # IPv6
                addr_ip = socket.inet_ntop(socket.AF_INET6, client_socket.recv(16))
            else:
                logging.warning("Unsupported address type %s from %s", atyp, addr)
                client_socket.close()
                return

            # 讀取目標端口
            port_bytes = client_socket.recv(2)
            if len(port_bytes) != 2:
                logging.warning("Invalid port bytes from %s", addr)
                client_socket.close()
                return
            port = int.from_bytes(port_bytes, 'big')
            logging.info("Connecting to target %s:%s from client %s", addr_ip, port, addr)
            
            # 建立到目標服務器的連線
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(self.timeout)
            remote.connect((addr_ip, port))
            
            # 回覆客戶端：連接成功
            reply = b'\x05\x00\x00\x01' + socket.inet_aton('0.0.0.0') + b'\x00\x00'
            client_socket.sendall(reply)
            
            # 開啟雙向數據轉發的線程，實現數據中繼
            t1 = threading.Thread(target=forward, args=(client_socket, remote))
            t2 = threading.Thread(target=forward, args=(remote, client_socket))
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        except socket.timeout:
            logging.warning("Socket timeout with client %s", addr)
        except Exception as e:
            logging.exception("Exception while handling client %s: %s", addr, e)
        finally:
            try:
                client_socket.close()
            except Exception as e:
                logging.debug("Error closing client socket %s: %s", addr, e)
            if remote:
                try:
                    remote.close()
                except Exception as e:
                    logging.debug("Error closing remote socket for %s: %s", addr, e)

    def start(self):
        """
        啟動 SOCKS5 代理服務器，並監聽客戶端連接
        """
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 設置 SO_REUSEADDR，允許端口重用
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # 為了使 accept() 能夠定期檢查停止事件，設置超時
        self.server_socket.settimeout(1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        logging.info("SOCKS5 proxy server started on %s:%s", self.host, self.port)
        
        try:
            while not self.stop_event.is_set():
                try:
                    client, addr = self.server_socket.accept()
                    logging.info("Accepted connection from %s:%s", addr[0], addr[1])
                    # 使用線程池處理客戶端連接
                    self.executor.submit(self.handle_client, client, addr)
                except socket.timeout:
                    # accept() 超時，重新檢查停止事件
                    continue
                except KeyboardInterrupt:
                    logging.info("KeyboardInterrupt received in accept loop.")
                    self.stop_event.set()
                    break
                except Exception as e:
                    logging.exception("Exception in accept loop: %s", e)
        except KeyboardInterrupt:
            logging.info("Server shutting down due to KeyboardInterrupt.")
            self.stop_event.set()
        finally:
            # 主動關閉所有連接：先 shutdown，再 close
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)
            except Exception as e:
                logging.debug("Error during server socket shutdown: %s", e)
            try:
                self.server_socket.close()
            except Exception as e:
                logging.debug("Error closing server socket: %s", e)
            self.executor.shutdown(wait=True)
            logging.info("Server stopped gracefully.")

if __name__ == '__main__':
    server = Socks5Server(port=2454)
    server.start()
