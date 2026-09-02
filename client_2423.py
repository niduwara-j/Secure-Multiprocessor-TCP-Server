import socket
import sys
import getpass

# ANSI Color Codes for terminal formatting
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

current_user = None
session_token = None

def send_message(sock, payload):
    """Encapsulates payload into protocol framing 'LEN:<len>\n<payload>' and sends."""
    payload_bytes = payload.encode('utf-8')
    length = len(payload_bytes)

    message = f"LEN:{length}\n".encode('utf-8') + payload_bytes

    try:
        sock.sendall(message)
    except BrokenPipeError:
        print(f"{Colors.RED}⚠️ Server closed connection (rate limit or network error). Please reconnect.{Colors.RESET}")
        return False
    except Exception as e:
        print(f"{Colors.RED}⚠️ Error sending payload: {e}{Colors.RESET}")
        return False

    try:
        response = sock.recv(4096)
        if not response:
            print(f"{Colors.RED}⚠️ Server disconnected.{Colors.RESET}")
            return False

        resp_text = response.decode('utf-8').strip()
        format_server_response(resp_text)
        return resp_text
    except Exception as e:
        print(f"{Colors.RED}⚠️ Error receiving response from server: {e}{Colors.RESET}")
        return False

def format_server_response(resp_text):
    """Pretty prints server response and tracks tokens/user state."""
    global current_user, session_token

    if resp_text.startswith("OK"):
        print(f"{Colors.GREEN}[SERVER] {resp_text}{Colors.RESET}")
        if "Token: " in resp_text:
            session_token = resp_text.split("Token: ")[1].strip()
    elif "423" in resp_text:
        print(f"{Colors.YELLOW}[SERVER] {resp_text}{Colors.RESET}")
    else:
        print(f"{Colors.RED}[SERVER] {resp_text}{Colors.RESET}")

def print_menu():
    user_status = f"{Colors.GREEN}{current_user}{Colors.RESET}" if current_user else f"{Colors.YELLOW}Guest (Not logged in){Colors.RESET}"
    token_status = f"{Colors.CYAN}{session_token[:12]}...{Colors.RESET}" if session_token else "None"

    print(f"\n{Colors.BOLD}--- Interactive Menu ---{Colors.RESET} [User: {user_status} | Token: {token_status}]")
    print(f"{Colors.BOLD}1.{Colors.RESET} Register New Account")
    print(f"{Colors.BOLD}2.{Colors.RESET} Login")
    print(f"{Colors.BOLD}3.{Colors.RESET} Check Session Status")
    print(f"{Colors.BOLD}4.{Colors.RESET} Logout")
    print(f"{Colors.BOLD}5.{Colors.RESET} Send Custom Raw Command")
    print(f"{Colors.BOLD}6.{Colors.RESET} Quit")

def main():
    global current_user, session_token

    host = '127.0.0.1'
    port = 50423

    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port = int(sys.argv[2])

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
    except Exception as e:
        print(f"{Colors.RED}Failed to connect to server at {host}:{port} -> {e}{Colors.RESET}")
        sys.exit(1)

    print(f"{Colors.CYAN}{Colors.BOLD}===================================================={Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}  🚀 Connected to Secure TCP Server on {host}:{port} {Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}===================================================={Colors.RESET}")

    while True:
        print_menu()
        try:
            choice = input(f"{Colors.BOLD}Choice (1-6): {Colors.RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting client.")
            break

        if choice == '1': # Register
            print(f"\n{Colors.BOLD}--- REGISTER ---{Colors.RESET}")
            username = input("Enter Username (3-20 chars): ").strip()
            password = getpass.getpass("Enter Password: ").strip()
            confirm = getpass.getpass("Confirm Password: ").strip()

            if not username or not password:
                print(f"{Colors.RED}Username and password cannot be empty.{Colors.RESET}")
                continue
            if password != confirm:
                print(f"{Colors.RED}Passwords do not match!{Colors.RESET}")
                continue

            cmd = f"REGISTER {username} {password}"
            if not send_message(s, cmd):
                break

        elif choice == '2': # Login
            print(f"\n{Colors.BOLD}--- LOGIN ---{Colors.RESET}")
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ").strip()

            if not username or not password:
                print(f"{Colors.RED}Username and password are required.{Colors.RESET}")
                continue

            cmd = f"LOGIN {username} {password}"
            resp = send_message(s, cmd)
            if not resp:
                break
            if resp.startswith("OK"):
                current_user = username
                print(f"{Colors.GREEN}Logged in as {username}!{Colors.RESET}")

        elif choice == '3': # Status
            print(f"\n{Colors.BOLD}--- SESSION STATUS ---{Colors.RESET}")
            cmd = "STATUS"
            if not send_message(s, cmd):
                break

        elif choice == '4': # Logout
            print(f"\n{Colors.BOLD}--- LOGOUT ---{Colors.RESET}")
            cmd = f"LOGOUT {session_token}" if session_token else "LOGOUT"
            resp = send_message(s, cmd)
            if not resp:
                break
            if resp.startswith("OK"):
                current_user = None
                session_token = None

        elif choice == '5': # Raw command
            raw_cmd = input("Enter raw command (e.g., STATUS, REGISTER u p, etc.): ").strip()
            if raw_cmd:
                if not send_message(s, raw_cmd):
                    break

        elif choice in ('6', 'quit', 'exit', 'q'):
            print("Closing client session...")
            break
        else:
            print(f"{Colors.YELLOW}Invalid choice. Please select 1-6.{Colors.RESET}")

    s.close()
    print("Disconnected.")

if __name__ == "__main__":
    main()
