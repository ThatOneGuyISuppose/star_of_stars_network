import socket
import threading
import time
import sys
import os
import random

class Frame:
    def __init__(self, src, dest, crc=0x00, size=0, ack_type=0, data=b''): # Frame structure [SRC][DST][CRC][SIZE/ ACK][ACK type][data]
        self.src = src
        self.dest = dest
        self.crc = crc
        self.size = size
        self.ack_type = ack_type
        self.data = data
    
    def calculate_crc(self):
        total = self.src + self.dest + self.size + self.ack_type
        if self.data:
            total += sum(self.data)
        return total & 0xFF
    
    def to_bytes(self):
        self.crc = self.calculate_crc()
        return bytes([self.dest, self.src, self.crc, self.size, self.ack_type]) + self.data
    
    @classmethod
    def from_bytes(cls, frame_bytes):
        if len(frame_bytes) < 5:
            return None
        dest = frame_bytes[0]
        src = frame_bytes[1]
        crc = frame_bytes[2]
        size = frame_bytes[3]
        ack_type = frame_bytes[4]
        data = frame_bytes[5:5+size] if size > 0 else b''
        
        frame = cls(src, dest, crc, size, ack_type, data)
        return frame
    
    def verify_crc(self):
        calculated = self.calculate_crc()
        return self.crc == calculated
    
class CCS:
    def __init__(self, port=5000, firewall_file="firewall.txt"):
        self.port = port
        self.server_socket = None
        self.active = False
        self.cas_table = {}  # Maps CAS ID to socket
        self.global_forwarding_table = {}  # Maps node address to CAS ID
        self.firewall_rules = {}
        self.firewall_file = firewall_file
        self.lock = threading.Lock()
        
    def load_firewall(self):
        if not os.path.exists(self.firewall_file):
            print(f"[CCS] No firewall file found ({self.firewall_file})")
            return
        
        with open(self.firewall_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or ':' not in line:
                    continue
                parts = line.split(':')
                address = parts[0].strip()
                rule = parts[1].strip().lower()
                self.firewall_rules[address] = rule
                print(f"[CCS] (FIREWALL) Loaded rule:    {address}: {rule}")
    
    def check_firewall(self, dest_addr):
        # Check specific node rule
        if dest_addr in self.firewall_rules:
            if self.firewall_rules[dest_addr] == "local":
                return False  # Block global traffic
        
        # Check network rule (_#)
        network = dest_addr.split('_')[0] + "_#"
        if network in self.firewall_rules:
            if self.firewall_rules[network] == "local":
                return False  # Block global traffic
        
        return True  # Allow
    
    def start(self):
        self.active = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind(('localhost', self.port))
        except socket.error as e:
            print(f"[CCS] Failed to bind to port {self.port}: {e}")
            return
        
        self.server_socket.listen(10)
        print(f"[CCS] Initialized on port {self.port}")
        
        # Load firewall rules
        self.load_firewall()
        
        self.accept_connections()
    
    def accept_connections(self):
        while self.active:
            try:
                self.server_socket.settimeout(1)
                client_socket, address = self.server_socket.accept()
                print(f"[CCS] New CAS connection from {address}")
                
                # Handle CAS registration
                threading.Thread(target=self.handle_cas, args=(client_socket,), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.active:
                    print(f"[CCS] Error accepting connection: {e}")
                break
    
    def handle_cas(self, cas_socket):
        cas_id = None
        
        try:
            # Receive registration frame
            header = self.receive_bytes(cas_socket, 5)
            if not header:
                print(f"[CCS] Failed to receive registration header")
                return
            
            size = header[3]
            
            if size == 255:  # Registration frame
                reg_data = self.receive_bytes(cas_socket, size)
                if not reg_data:
                    print(f"[CCS] Failed to receive registration data")
                    return
                
                # Strip null bytes and decode
                reg_data_clean = reg_data.rstrip(b'\x00')
                reg_info = reg_data_clean.decode('utf-8', errors='ignore').strip()
                lines = [l.strip() for l in reg_info.split('\n') if l.strip()]
                
                if len(lines) == 0:
                    print(f"[CCS] Received empty registration")
                    return
                    
                cas_id = lines[0]
                
                with self.lock:
                    self.cas_table[cas_id] = cas_socket
                print(f"[CCS] (CAS {cas_id}) registered with {len(lines)-1} nodes")
                
                # Store node-to-CAS mappings
                for i in range(1, len(lines)):
                    if lines[i]:
                        node_addr = lines[i].strip()
                        self.global_forwarding_table[node_addr] = cas_id
                
                # Send firewall rules to CAS
                self.send_firewall(cas_socket, cas_id)
            else:
                print(f"[CCS] Unexpected frame size during registration: {size}")
                return
            
            # Now handle data frames from this CAS
            while self.active:
                frame_bytes = self.receive_frame(cas_socket)
                if not frame_bytes:
                    break
                
                frame = Frame.from_bytes(frame_bytes)
                if not frame:
                    print(f"[CCS] (CAS {cas_id}) provided invalid frame")
                    continue
                
                print(f"[CCS] (CAS {cas_id}) received frame from {frame.src >> 4}_{frame.src & 0x0F} to {frame.dest >> 4}_{frame.dest & 0x0F}")
                self.forward_global_frame(frame, cas_id)
                
        except Exception as e:
            print(f"[CCS] Error handling CAS {cas_id}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if cas_id:
                with self.lock:
                    if cas_id in self.cas_table:
                        del self.cas_table[cas_id]
                print(f"[CCS] (CAS {cas_id}) connection closed")
    
    def send_firewall(self, cas_socket, cas_id):
        rules_to_send = []
        network_num = cas_id.split('_')[0]
        
        for addr, rule in self.firewall_rules.items():
            if addr.startswith(network_num):
                rules_to_send.append(f"{addr}:{rule}")
        
        if rules_to_send:
            rules_str = '\n'.join(rules_to_send)
            rules_bytes = rules_str.encode('utf-8')
            # Special frame: src=0, dest=0, size=254 indicates firewall rules
            frame = Frame(0, 0, size=len(rules_bytes), data=rules_bytes)
            frame.size = min(254, len(rules_bytes))  # Use 254 as firewall indicator
            try:
                cas_socket.sendall(frame.to_bytes())
            except Exception as e:
                print(f"[CCS] Error sending firewall rules to (CAS {cas_id}): {e}")
    
    def forward_global_frame(self, frame, src_cas_id):
        src_addr = f"{frame.src >> 4}_{frame.src & 0x0F}"
        dest_addr = f"{frame.dest >> 4}_{frame.dest & 0x0F}"
        
        print(f"[CCS] Processing frame: {src_addr} to {dest_addr}", end="")
        
        # Check firewall
        if not self.check_firewall(dest_addr):
            print(f"    (FIREWALLED)")
            # Send NACK (0x02 = firewalled)
            nack = Frame(frame.dest, frame.src, size=0, ack_type=0x02)
            with self.lock:
                if src_cas_id in self.cas_table:
                    try:
                        self.cas_table[src_cas_id].sendall(nack.to_bytes())
                    except:
                        pass
            return
        else:
            print() # Formatting
        # Find destination CAS
        dest_cas_id = self.global_forwarding_table.get(dest_addr)
        
        if dest_cas_id and dest_cas_id in self.cas_table:
            print(f"[CCS] Forwarding {src_addr} -> {dest_addr} via CAS {dest_cas_id}")
            with self.lock:
                try:
                    self.cas_table[dest_cas_id].sendall(frame.to_bytes())
                    print(f"[CCS] Successfully forwarded frame from {src_addr} to (CAS {dest_cas_id})")
                except Exception as e:
                    print(f"[CCS] Error forwarding to (CAS {dest_cas_id}): {e}")
        else:
            print(f"[CCS] Unknown destination CAS for {dest_addr}, cannot forward")
    
    def receive_bytes(self, sock, n):
        time.sleep(0.1)
        data = b''
        while len(data) < n:
            try:
                chunk = sock.recv(n - len(data))
                if not chunk:
                    print(f"[CCS] receive_bytes: connection closed, received {len(data)}/{n} bytes")
                    return None
                data += chunk
            except Exception as e:
                return None
        return data
    
    def receive_frame(self, sock):
        header = self.receive_bytes(sock, 5)
        if not header:
            return None
        
        size = header[3]
        if size > 0:
            data = self.receive_bytes(sock, size)
            if not data:
                return None
            return header + data
        return header
    
    def stop(self):
        self.active = False
        if self.server_socket:
            self.server_socket.close()
        
        # Make a copy of the sockets to avoid dictionary modification during iteration
        with self.lock:
            sockets_to_close = list(self.cas_table.values())
        
        for sock in sockets_to_close:
            try:
                sock.close()
            except:
                pass



class CAS:
    def __init__(self, network_id, local_port, ccs_port=5000):
        self.network_id = network_id
        self.local_port = local_port
        self.ccs_port = ccs_port
        self.server_socket = None
        self.ccs_socket = None
        self.active = False
        self.switching_table = {}
        self.local_nodes = []
        self.firewall_rules = {}
        self.lock = threading.Lock()
        
    def start(self):
        self.active = True
        
        # Start local server for nodes
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind(('localhost', self.local_port))
        except socket.error as e:
            print(f"  [CAS {self.network_id}] Failed to bind to port {self.local_port}: {e}")
            return
        
        self.server_socket.listen(16)
        print(f"  [CAS {self.network_id}] Started on port {self.local_port}")
        
        # Connect to CCS
        time.sleep(0.5)
        self.connect_to_ccs()
        
        # Accept node connections
        threading.Thread(target=self.accept_connections, daemon=True).start()
        
        # Wait for nodes to connect, then register with CCS
        time.sleep(3)
        self.register_with_ccs()
    
    def connect_to_ccs(self):
        try:
            self.ccs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.ccs_socket.connect(('localhost', self.ccs_port))
            print(f"  [CAS {self.network_id}] Connected to CCS")
            
            # Start thread to handle CCS messages
            threading.Thread(target=self.handle_ccs, daemon=True).start()
        except Exception as e:
            print(f"  [CAS {self.network_id}] Failed to connect to CCS: {e}")
    
    def register_with_ccs(self):
        if not self.ccs_socket:
            return
        
        # Build registration message with all connected nodes
        reg_info = f"{self.network_id}\n"
        
        with self.lock:
            # Get all unique node IDs from switching table
            registered_nodes = set()
            for addr in self.switching_table.keys():
                node_id = addr & 0x0F
                registered_nodes.add(node_id)
            
            for node_id in sorted(registered_nodes):
                node_addr = f"{self.network_id}_{node_id}"
                reg_info += f"{node_addr}\n"
        
        reg_bytes = reg_info.encode('utf-8')
        
        # Pad to 255 bytes
        if len(reg_bytes) < 255:
            reg_bytes = reg_bytes + b'\x00' * (255 - len(reg_bytes))
        elif len(reg_bytes) > 255:
            reg_bytes = reg_bytes[:255]
        
        # Special registration frame
        frame = Frame(0, 0, size=255, data=reg_bytes)
        frame_bytes = frame.to_bytes()
        
        try:
            self.ccs_socket.sendall(frame_bytes)
            print(f"  [CAS {self.network_id}] Registered with CCS: {sorted(registered_nodes)}")
        except Exception as e:
            print(f"  [CAS {self.network_id}] Error registering with CCS: {e}")
    
    def handle_ccs(self):
        try:
            while self.active:
                frame_bytes = self.receive_frame(self.ccs_socket)
                if not frame_bytes:
                    break
                
                frame = Frame.from_bytes(frame_bytes)
                if not frame:
                    continue
                
                # Check if it's firewall rules (size=254, src=0, dest=0)
                if frame.size == 254 and frame.src == 0 and frame.dest == 0:
                    rules_str = frame.data.decode('utf-8')
                    for line in rules_str.split('\n'):
                        if ':' in line:
                            addr, rule = line.split(':')
                            self.firewall_rules[addr.strip()] = rule.strip()
                    print(f"  [CAS {self.network_id}] Received firewall rules from CCS")
                else:
                    # Regular data frame from CCS - forward to local node
                    print(f"  [CAS {self.network_id}] Received frame from CCS: {frame.src >> 4}_{frame.src & 0x0F} to {frame.dest >> 4}_{frame.dest & 0x0F}")
                    self.forward_to_local(frame)
        except Exception as e:
            if self.active:
                print(f"  [CAS {self.network_id}] Error in CCS handler: {e}")
                import traceback
                traceback.print_exc()
    
    def accept_connections(self):
        while self.active:
            try:
                self.server_socket.settimeout(1)
                client_socket, address = self.server_socket.accept()
                print(f"  [CAS {self.network_id}] New node connection from {address}")
                threading.Thread(target=self.handle_node, args=(client_socket,), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.active:
                    print(f"  [CAS {self.network_id}] Error accepting connection: {e}")
                break
    
    def handle_node(self, node_socket):
        node_addr = None
        try:
            # First frame from node should register it
            first_frame = self.receive_frame(node_socket)
            if not first_frame:
                return
            
            frame = Frame.from_bytes(first_frame)
            if not frame:
                return
            
            # Register node
            node_addr = frame.src
            node_id = frame.src & 0x0F
            src_network = frame.src >> 4
            
            with self.lock:
                self.switching_table[node_addr] = node_socket
                if node_id not in self.local_nodes:
                    self.local_nodes.append(node_id)
            
            print(f"  [CAS {self.network_id}] Registered node {src_network}_{node_id} with address {node_addr}")
            
            # Process frames
            self.forward_frame(frame)
            while self.active:
                frame_bytes = self.receive_frame(node_socket)
                if not frame_bytes:
                    break
                
                frame = Frame.from_bytes(frame_bytes)
                if not frame:
                    continue
                
                self.forward_frame(frame)
                
        except Exception as e:
            print(f"  [CAS {self.network_id}] Error handling node: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if node_addr and node_addr in self.switching_table:
                with self.lock:
                    del self.switching_table[node_addr]
    
    def forward_frame(self, frame):
        dest_network = frame.dest >> 4
        dest_node = frame.dest & 0x0F
        src_network = frame.src >> 4
        src_node = frame.src & 0x0F
        
        # Check if destination is local
        if dest_network == self.network_id:
            # Check local firewall
            node_addr = f"{self.network_id}_{dest_node}"
            if node_addr in self.firewall_rules and self.firewall_rules[node_addr] == "local":
                # Block and send NACK
                nack = Frame(frame.dest, frame.src, size=0, ack_type=0x02)
                with self.lock:
                    src_socket = self.switching_table.get(frame.src)
                    if src_socket:
                        try:
                            src_socket.sendall(nack.to_bytes())
                        except:
                            pass
                return
            
            # Forward locally
            self.forward_to_local(frame)
        else:
            # Check if global traffic is allowed for source
            src_addr = f"{src_network}_{src_node}"
            network_rule = f"{src_network}_#"
            if (src_addr in self.firewall_rules and self.firewall_rules[src_addr] == "local") or \
               (network_rule in self.firewall_rules and self.firewall_rules[network_rule] == "local"):
                # Block global traffic from this node/network
                print(f"  [CAS {self.network_id}] (FIREWALL) Blocking global traffic from {src_addr}")
                nack = Frame(frame.dest, frame.src, size=0, ack_type=0x02)
                with self.lock:
                    src_socket = self.switching_table.get(frame.src)
                    if src_socket:
                        try:
                            src_socket.sendall(nack.to_bytes())
                        except:
                            pass
                return
            
            # Forward to CCS for global routing
            if self.ccs_socket:
                try:
                    print(f"  [CAS {self.network_id}] (GLOBAL) Forwarding to node {dest_network}_{dest_node} by CCS")
                    self.ccs_socket.sendall(frame.to_bytes())
                except Exception as e:
                    print(f"  [CAS {self.network_id}] Error forwarding to CCS: {e}")
    
    def forward_to_local(self, frame):
        dest_network = frame.dest >> 4
        dest_node = frame.dest & 0x0F
        
        with self.lock:
            dest_socket = self.switching_table.get(frame.dest)
            if dest_socket:
                try:
                    print(f"  [CAS {self.network_id}] (LOCAL) Forwarding to node {dest_network}_{dest_node}")
                    dest_socket.sendall(frame.to_bytes())
                except Exception as e:
                    print(f"  [CAS {self.network_id}] Error forwarding to node {dest_network}_{dest_node}: {e}")
            else:
                print(f"  [CAS {self.network_id}] No socket found for destination {dest_network}_{dest_node} (addr={frame.dest})")
                print(f"  [CAS {self.network_id}] Available nodes: {list(self.switching_table.keys())}")
    
    def receive_frame(self, sock):
        try:
            header = b''
            while len(header) < 5:
                chunk = sock.recv(5 - len(header))
                if not chunk:
                    return None
                header += chunk
            
            size = header[3]
            if size > 0:
                data = b''
                while len(data) < size:
                    chunk = sock.recv(size - len(data))
                    if not chunk:
                        return None
                    data += chunk
                return header + data
            return header
        except:
            return None
    
    def stop(self):
        self.active = False
        if self.server_socket:
            self.server_socket.close()
        if self.ccs_socket:
            self.ccs_socket.close()


class Node:
    def __init__(self, network_id, node_id, cas_port):
        self.network_id = network_id
        self.node_id = node_id
        self.address = (network_id << 4) | node_id  # Combine into single byte
        self.cas_port = cas_port
        self.socket = None
        self.active = False
        self.pending_frames = {}  # Buffer for unacknowledged frames
        self.data_received = []
        self.lock = threading.Lock()
        self.max_retries = 3
        
    def start(self):
        self.active = True
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            self.socket.connect(('localhost', self.cas_port))
            print(f"    [NODE {self.network_id}_{self.node_id}] Connected to CAS")
        except Exception as e:
            print(f"    [NODE {self.network_id}_{self.node_id}] Failed to connect: {e}")
            return
        
        # Send a registration frame immediately (empty frame with our address)
        reg_frame = Frame(self.address, self.address, size=0, ack_type=0)
        try:
            self.socket.sendall(reg_frame.to_bytes())
            print(f"    [NODE {self.network_id}_{self.node_id}] Sent registration frame")
        except Exception as e:
            print(f"    [NODE {self.network_id}_{self.node_id}] Failed to register: {e}")
            return
        
        # Start receiver thread
        threading.Thread(target=self.receive_loop, daemon=True).start()
        
        # Wait for all nodes to connect and register
        time.sleep(2)
        
        self.send_data()
        
        # Wait for responses
        time.sleep(3)
        self.write_output()
        self.active = False
    
    def send_data(self):
        filename = f"node{self.network_id}_{self.node_id}.txt"
        if not os.path.exists(filename):
            print(f"    [NODE {self.network_id}_{self.node_id}] No input file")
            return
        
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or ':' not in line:
                    continue
                
                parts = line.split(':', 1)
                dest_str = parts[0].strip()
                data = parts[1].strip()
                
                dest_parts = dest_str.split('_')
                dest_network = int(dest_parts[0])
                dest_node = int(dest_parts[1])
                dest_addr = (dest_network << 4) | dest_node
                
                self.send_frame(dest_addr, data)
                time.sleep(0.1)
    
    def send_frame(self, dest_addr, data):
        data_bytes = data.encode('utf-8')
        
        # Add error to frame
        if random.random() < 0.05:
            # Corrupt one byte of data
            if len(data_bytes) > 0:
                corrupted = bytearray(data_bytes)
                corrupted[0] ^= 0xFF
                data_bytes = bytes(corrupted)
                print(f"    [NODE {self.network_id}_{self.node_id}] Added error to frame")
        
        frame = Frame(self.address, dest_addr, size=len(data_bytes), data=data_bytes)
        frame_id = (dest_addr, time.time())
        
        dest_net = dest_addr >> 4
        dest_node = dest_addr & 0x0F
        
        print(f"    [NODE {self.network_id}_{self.node_id}] Sending frame: my_addr={self.address}, dest_addr={dest_addr} ({dest_net}_{dest_node}), size={len(data_bytes)}")
        
        with self.lock:
            self.pending_frames[frame_id] = (frame, 0)  # (frame, retry_count)
        
        try:
            self.socket.sendall(frame.to_bytes())
            print(f"    [NODE {self.network_id}_{self.node_id}] Sent to {dest_net}_{dest_node}: {data[:20]}...")
        except Exception as e:
            print(f"    [NODE {self.network_id}_{self.node_id}] Send error: {e}")
    
    def receive_loop(self):
        while self.active:
            try:
                frame_bytes = self.receive_frame()
                if not frame_bytes:
                    continue
                
                frame = Frame.from_bytes(frame_bytes)
                if not frame:
                    continue
                
                if frame.size == 0:  # ACK frame
                    self.handle_ack(frame)
                else:  # Data frame
                    self.handle_data(frame)
                    
            except Exception as e:
                if self.active:
                    print(f"    [NODE {self.network_id}_{self.node_id}] Receive error: {e}")
                break
    
    def handle_data(self, frame):
        # Fail to acknowledge frame
        if random.random() < 0.05:
            print(f"    [NODE {self.network_id}_{self.node_id}] Failed to acknowledge frame")
            return
        
        # Verify CRC
        if not frame.verify_crc():
            print(f"    [NODE {self.network_id}_{self.node_id}] CRC error")
            # Send NACK for CRC error (0x01)
            ack = Frame(self.address, frame.src, size=0, ack_type=0x01)
            try:
                self.socket.sendall(ack.to_bytes())
            except:
                pass
            return
        
        # Store data
        src_network = frame.src >> 4
        src_node = frame.src & 0x0F
        data = frame.data.decode('utf-8')
        
        with self.lock:
            self.data_received.append((f"{src_network}_{src_node}", data))
        
        print(f"    [NODE {self.network_id}_{self.node_id}] Received data from {src_network}_{src_node}")
        
        # Send positive ACK (0x03)
        ack = Frame(self.address, frame.src, size=0, ack_type=0x03)
        try:
            self.socket.sendall(ack.to_bytes())
        except Exception as e:
            print(f"    [NODE {self.network_id}_{self.node_id}] Error sending ACK: {e}")
    
    def handle_ack(self, frame):
        ack_type = frame.ack_type
        
        if ack_type == 0x03:  # Positive ACK
            # Remove from pending
            with self.lock:
                for key in list(self.pending_frames.keys()):
                    if key[0] == frame.src:
                        del self.pending_frames[key]
                        break
            print(f"    [NODE {self.network_id}_{self.node_id}] Received ACK from {frame.src >> 4}_{frame.src & 0x0F}")
        
        elif ack_type == 0x01:  # CRC error - resend
            print(f"    [NODE {self.network_id}_{self.node_id}] CRC error, resending")
            # Implement retry logic here
        
        elif ack_type == 0x02:  # Firewalled
            print(f"    [NODE {self.network_id}_{self.node_id}] Frame firewalled")
            with self.lock:
                for key in list(self.pending_frames.keys()):
                    if key[0] == frame.src:
                        del self.pending_frames[key]
                        break
    
    def receive_frame(self):
        try:
            self.socket.settimeout(1)
            header = b''
            while len(header) < 5:
                chunk = self.socket.recv(5 - len(header))
                if not chunk:
                    return None
                header += chunk
            
            size = header[3]
            if size > 0:
                data = b''
                while len(data) < size:
                    chunk = self.socket.recv(size - len(data))
                    if not chunk:
                        return None
                    data += chunk
                return header + data
            return header
        except socket.timeout:
            return None
        except:
            return None
    
    def write_output(self):      
        if self.data_received:
            filename = f"node{self.network_id}_{self.node_id}output.txt"
            with open(filename, 'w') as f:
                for src, data in self.data_received:
                    f.write(f"{src}: {data}\n")
            print(f"    [NODE {self.network_id}_{self.node_id}] Wrote {len(self.data_received)} lines to {filename}")
        else:
            print(f"    [NODE {self.network_id}_{self.node_id}] No data received")
            


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 SoSs.py <CAS 1 Num of Nodes> <CAS 2 Num of Nodes> ...")
        print("Example: python3 SoSs.py 2 6 4")
        sys.exit(1)

    networks = {}
    for i in range(1, len(sys.argv)):
        network_id = i
        num_nodes = int(sys.argv[i])
        networks[network_id] = num_nodes
    # Start CCS
    ccs = CCS(port=5000)
    ccs_thread = threading.Thread(target=ccs.start, daemon=True)
    ccs_thread.start()
    time.sleep(0.5)
    
    # Start CAS switches
    cas_switches = []
    base_port = 5001
    for network_id in sorted(networks.keys()):
        cas = CAS(network_id, base_port + network_id - 1, ccs_port=5000)
        cas_thread = threading.Thread(target=cas.start, daemon=True)
        cas_thread.start()
        cas_switches.append(cas)
        time.sleep(0.5)
    
    time.sleep(1)
    
    # Start nodes
    node_threads = []
    for network_id, num_nodes in networks.items():
        cas_port = base_port + network_id - 1
        for node_id in range(1, num_nodes + 1):
            node = Node(network_id, node_id, cas_port)
            node_thread = threading.Thread(target=node.start, daemon=False)
            node_thread.start()
            node_threads.append(node_thread)
            time.sleep(0.1)
    
    # Wait for all nodes to complete
    for thread in node_threads:
        thread.join()
    
    print("\n[MAIN] Nodes completed. Closing...")
    
    # Cleanup
    for cas in cas_switches:
        cas.stop()
    ccs.stop()
    
    time.sleep(1)
    print("[MAIN] Exit")

if __name__ == "__main__":
    main()