#!/usr/bin/env python3
import sys
import subprocess
import re
import os
import argparse
import socket
import errno
import datetime

tcp_port = 9999

class Tee:
    def __init__(self, filename, stream):
        # stream는 원래 출력 스트림(참고용)이나, 우리는 파일에만 기록한다.
        self.file = open(filename, 'a', encoding='utf-8')
    def write(self, data):
        self.file.write(data)
    def flush(self):
        self.file.flush()
    def close(self):
        self.file.close()

def run_command(cmd, capture_output=True, shell=False):
    try:
        result = subprocess.run(cmd,
                                stdout=subprocess.PIPE if capture_output else None,
                                stderr=subprocess.STDOUT,
                                shell=shell,
                                check=True,
                                universal_newlines=True)
        return result.stdout.strip() if result.stdout is not None else ""
    except subprocess.CalledProcessError as e:
        return e.stdout.strip() if e.stdout is not None else ""

def run_sudo(cmd_list, capture_output=True):
    sudo_cmd = ["sudo"] + cmd_list
    return run_command(sudo_cmd, capture_output=capture_output)

def extract_probe_info(output):
    m = re.search(r'Prober=([\d\.]+):(\d+)', output)
    if m:
        return m.group(1), m.group(2)
    return None, None

##############################
# F-PMTUD related functions
def run_fpmtd_prober(dest_ip):
    print("[F-PMTUD, prober] Starting mtud_prober with destination IP: " + dest_ip, file=sys.stderr)
    cmd = ["./mtud_prober", "-i", dest_ip, "-p", "9999"]
    return run_sudo(cmd, capture_output=True)

def run_fpmtd_prober_with_probe(dest_ip, probe_port):
    print("[F-PMTUD, destination] Starting mtud_prober with destination IP: {} and probe port: {}".format(dest_ip, probe_port), file=sys.stderr)
    cmd = ["./mtud_prober", "-i", dest_ip, "-p", probe_port, "-P", "9999"]
    return run_sudo(cmd, capture_output=True)

def run_fpmtd_destination():
    print("[F-PMTUD] Starting mtud_destination ...", file=sys.stderr)
    cmd = ["./mtud_destination"]
    return run_sudo(cmd, capture_output=True)

##############################
# MSS Clamping related functions
def get_peer_mss(target_host, target_port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)

        sock.connect((target_host, target_port))
        print(f"Connected to {target_host}:{target_port}")

        # Prober 측 소켓에서 확인한 MSS
        peer_mss = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
        print(f"Prober received MSS: {peer_mss} bytes")

        # Daemon(서버)로부터도 MSS 안내를 받아 출력
        received_data = sock.recv(1024).decode('utf-8')
        print(f"Received MSS from daemon: {received_data}")

    except socket.timeout:
        print(f"Connection to {target_host}:{target_port} timed out after 5 seconds.")
        return False
    except socket.error as e:
        if isinstance(e, socket.error) and e.errno == errno.ECONNREFUSED:
            print(f"Connection refused by {target_host}:{target_port}")
        else:
            print(f"Socket error: {e}")
        return False
    finally:
        sock.close()
        return True

def run_daemon(port):
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        server_sock.bind(("0.0.0.0", port))
        server_sock.listen(30)
        print(f"MSS Claping checker: Listening on port {port}...")

        while True:
            client_sock, client_addr = server_sock.accept()
            print(f"Connection accepted from {client_addr}")
            try:
                # 연결된 소켓에서 서버가 인지하는 MSS
                peer_mss = client_sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
                msg = f"\nDaemon received MSS: {peer_mss} bytes"
                client_sock.sendall(msg.encode('utf-8'))
            except client_sock.error as e:
                print(f"Error handling client {client_addr}: {e}")
            finally:
                client_sock.close()
                break

    except KeyboardInterrupt:
        print("Daemon mode stopped by user.")
    except socket.error as e:
        print(f"Socket error in daemon mode: {e}")
    finally:
        server_sock.close()

##############################
def setup_output_filename(test_name, role):
    """
    파일명 끝에 현재 날짜/시간(초 단위까지)을 추가.
    예: F-PMTUD_destination_result_20250123235959.txt
    """
    now = datetime.datetime.utcnow()
    timestamp_str = now.strftime("%Y%m%d%H%M%S")
    return f"{test_name}_{role}_result_{timestamp_str}.txt"

def run_prober_tests(dest_ip):
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    sys.stderr = open(os.devnull, 'w')
    
    # 2. MSS Clamping
    run_sudo(["ip", "route", "flush", "cache"])

    filename = setup_output_filename("MSS", "prober")
    tee = Tee(filename, original_stdout)
    sys.stdout = tee
    mss_result = get_peer_mss(dest_ip, tcp_port)
    sys.stdout = original_stdout
    tee.close()

    mss_result = "SUCCESS" if mss_result is True else "FAILED"

    # 1. F-PMTUD prober test
    run_sudo(["ip", "route", "flush", "cache"])

    filename = setup_output_filename("F-PMTUD", "prober")
    tee = Tee(filename, original_stdout)
    sys.stdout = tee
    print("[F-PMTUD, prober] First phase: mtud_prober\n")
    output1 = run_fpmtd_prober(dest_ip)
    print("===== mtud_prober (prober) Output =====")
    print(output1)
    print("\n[F-PMTUD, prober] Second phase: mtud_destination\n")
    output2 = run_fpmtd_destination()
    print("===== mtud_destination (prober) Output =====")
    print(output2)
    sys.stdout = original_stdout
    tee.close()

    fpmtd_prober_result = "SUCCESS" if "SUCCESS" in output1.upper() else "FAILED"

    sys.stderr.close()
    sys.stderr = original_stderr

    print("F-PMTUD_prober " + fpmtd_prober_result)
    print("MSS prober " + mss_result)

def run_destination_tests():
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    sys.stderr = open(os.devnull, 'w')
    
    # 2. MSS clamping test
    run_sudo(["ip", "route", "flush", "cache"])
    run_daemon(tcp_port)

    # 1. F-PMTUD destination test
    run_sudo(["ip", "route", "flush", "cache"])

    filename = setup_output_filename("F-PMTUD", "destination")
    tee = Tee(filename, original_stdout)
    sys.stdout = tee
    print("[F-PMTUD, destination] First phase: mtud_destination\n")
    output1 = run_fpmtd_destination()
    print("===== mtud_destination (destination) Output =====")
    print(output1)
    probe_ip, probe_port = extract_probe_info(output1)
    if not probe_ip or not probe_port:
        print("[F-PMTUD, destination] Failed to extract probe info from mtud_destination output.")
        sys.stdout = original_stdout
        tee.close()
        sys.stderr.close()
        sys.stderr = original_stderr
        sys.exit(1)
    print("\n[F-PMTUD, destination] Second phase: mtud_prober with -i {} -p {}\n".format(probe_ip, probe_port))
    output2 = run_fpmtd_prober_with_probe(probe_ip, probe_port)
    print("===== mtud_prober (destination) Output =====")
    print(output2)
    sys.stdout = original_stdout
    tee.close()
    fpmtd_destination_result = "SUCCESS" if "SUCCESS" in output2.upper() else "FAILED"

    sys.stderr.close()
    sys.stderr = original_stderr

    print("F-PMTUD_destination " + fpmtd_destination_result)

def main():
    parser = argparse.ArgumentParser(
        description="Integrated F-PMTUD, F-PMTUD_setDF, and MSS Clamping tests"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--prober", metavar="DEST_IP",
                       help="Run as Prober (destination IP required)")
    group.add_argument("-d", "--destination", action="store_true",
                       help="Run as Destination")
    args = parser.parse_args()

    if args.prober:
        run_prober_tests(args.prober)
    elif args.destination:
        run_destination_tests()

if __name__ == "__main__":
    main()
