import os, hashlib, hmac, random, re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from colorama import init, Fore, Style

# Inicializar colorama
init(autoreset=True)

# Clase de gestión de semillas para Provably Fair
class SeedManager:
    def __init__(self, encryption_key):
        self.encryption_key = encryption_key
        self.server_seed = self.generate_server_seed()
        self.client_seed = self.generate_client_seed()
        self.nonce = 0

    def generate_server_seed(self):
        return hashlib.sha256(str(random.getrandbits(256)).encode('utf-8')).hexdigest()

    def generate_client_seed(self):
        return hashlib.sha256(str(random.getrandbits(256)).encode('utf-8')).hexdigest()

    def encrypt_seed(self, seed):
        backend = default_backend()
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=backend
        )
        key = kdf.derive(self.encryption_key.encode())
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(seed.encode()) + encryptor.finalize()
        return salt + iv + ct

    def decrypt_seed(self, encrypted_seed):
        backend = default_backend()
        salt = encrypted_seed[:16]
        iv = encrypted_seed[16:32]
        ct = encrypted_seed[32:]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=backend
        )
        key = kdf.derive(self.encryption_key.encode())
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
        decryptor = cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()

    def generate_random_number(self, nonce):
        message = f"{self.server_seed}:{self.client_seed}:{nonce}".encode('utf-8')
        hash_result = hmac.new(self.server_seed.encode('utf-8'), message, hashlib.sha256).hexdigest()
        random_value = int(hash_result, 16) % 37
        return random_value

    def verify_random_number(self, random_number, nonce):
        message = f"{self.server_seed}:{self.client_seed}:{nonce}".encode('utf-8')
        hash_result = hmac.new(self.server_seed.encode('utf-8'), message, hashlib.sha256).hexdigest()
        random_value = int(hash_result, 16) % 37
        return random_number == random_value

# Clase para la ruleta
class Roulette:
    def __init__(self):
        self.numbers = list(range(1, 37)) + [0]
        self.colors = {i: 'red' if i in [
            1, 3, 5, 7, 9, 12, 14, 16, 18, 19, 21, 23, 25, 27, 30, 32, 34, 36
        ] else 'black' for i in range(1, 37)}
        self.colors.update({0: 'green'})

    def color_of(self, number):
        return self.colors[number]

    def display_number(self, number):
        color = self.color_of(number)
        if color == 'red':
            return Fore.RED + str(number) + Style.RESET_ALL
        elif color == 'black':
            return Fore.BLACK + str(number) + Style.RESET_ALL
        elif color == 'green':
            return Fore.GREEN + str(number) + Style.RESET_ALL

# Clase para las apuestas
class Bet:
    def __init__(self, amount, bet_type, bet_value):
        self.amount = amount
        self.bet_type = bet_type
        self.bet_value = bet_value

    def payout(self, result, color):
        payouts = {
            'number': 35,
            'color': 1,
            'odd/even': 1,
            'high/low': 1,
            'dozen': 2,
            'column': 2
        }

        if self.bet_type == 'number' and self.bet_value == result:
            return self.amount * (payouts['number'] + 1)
        elif self.bet_type == 'color' and self.bet_value == color:
            return self.amount * (payouts['color'] + 1)
        elif self.bet_type == 'odd/even' and (
            (self.bet_value == 'odd' and result % 2 != 0) or
            (self.bet_value == 'even' and result % 2 == 0)
        ):
            return self.amount * (payouts['odd/even'] + 1)
        elif self.bet_type == 'high/low' and (
            (self.bet_value == 'high' and 19 <= result <= 36) or
            (self.bet_value == 'low' and 1 <= result <= 18)
        ):
            return self.amount * (payouts['high/low'] + 1)
        elif self.bet_type == 'dozen' and (
            (self.bet_value == '1st' and 1 <= result <= 12) or
            (self.bet_value == '2nd' and 13 <= result <= 24) or
            (self.bet_value == '3rd' and 25 <= result <= 36)
        ):
            return self.amount * (payouts['dozen'] + 1)
        elif self.bet_type == 'column' and (
            (self.bet_value == '1st' and result in range(1, 37, 3)) or
            (self.bet_value == '2nd' and result in range(2, 37, 3)) or
            (self.bet_value == '3rd' and result in range(3, 37, 3))
        ):
            return self.amount * (payouts['column'] + 1)
        else:
            return 0

# Clase para el jugador
class Player:
    def __init__(self, name, balance):
        self.name = name
        self.balance = balance

    def place_bet(self, amount, bet_type, bet_value):
        if amount > self.balance:
            print(Fore.RED + "Insufficient balance" + Style.RESET_ALL)
            return None
        self.balance -= amount
        return Bet(amount, bet_type, bet_value)

    def collect_winnings(self, amount):
        self.balance += amount

    def refund_bet(self, amount):
        self.balance += amount
        print(Fore.RED + f"The bet of ${amount} has been refunded due to verification failure.\n" + Style.RESET_ALL)


# Función para centrar una cadena en la consola
def print_centered(input_string, total_width):

    # Función para calcular la longitud visual de la cadena (sin colores)
    def visual_length(vl_input_string):
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return len(ansi_escape.sub('', vl_input_string))
    
    # Longitud visual de la cadena original
    length_without_colors = visual_length(input_string)

    # Calcular espacios en blanco para centrado
    padding = (total_width - length_without_colors) // 2
    left_padding = padding
    right_padding = total_width - length_without_colors - left_padding

    # Construir cadena centrada
    vl_output_string = f"{' ' * left_padding}{input_string}{' ' * right_padding}"
    print(vl_output_string)
    return vl_output_string

# Función para mostrar la cabecera
def display_header():
    print(Fore.GREEN + "=" * 40)
    print(Fore.GREEN + "THE FAIR ROULETTE".center(40))
    print(Fore.GREEN + "=" * 40 + Style.RESET_ALL)

# Función principal del juego
def main(player_name="John Doe", initial_balance=1000):
    encryption_key = "secret_key"
    seed_manager = SeedManager(encryption_key)
    roulette = Roulette()
    player = Player(player_name, initial_balance)

    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            display_header()
            player_info = f"Player: {Fore.CYAN}{player.name}{Style.RESET_ALL}, Balance: {Fore.YELLOW}${player.balance}{Style.RESET_ALL}"
            print_centered(player_info, 40)
            print("\n" + Fore.BLUE + "Place your bet!".center(40) + Style.RESET_ALL)
            print(Fore.GREEN + "-" * 40 + Style.RESET_ALL)
            print(""" - Number (0, 1-36)
 - Color (Red, Black)
 - Odd/Even
 - High/Low (1-18, 19-36)
 - Dozen (1st, 2nd, 3rd)
 - Column (1st, 2nd, 3rd)
""")
            bet_type = input("Selection: ").strip().lower()
            if bet_type == 'number':
                bet_value = int(input("Enter the number (0, 1-36): ").strip())
            elif bet_type == 'color':
                bet_value = input("Enter the color (red, black): ").strip().lower()
            elif bet_type == 'odd/even':
                bet_value = input("Enter (odd, even): ").strip().lower()
            elif bet_type == 'high/low':
                bet_value = input("Enter (high, low): ").strip().lower()
            elif bet_type == 'dozen':
                bet_value = input("Enter (1st, 2nd, 3rd): ").strip().lower()
            elif bet_type == 'column':
                bet_value = input("Enter (1st, 2nd, 3rd): ").strip().lower()
            else:
                print(Fore.RED + "Invalid bet type" + Style.RESET_ALL)
                continue

            amount = int(input("Enter the bet amount: ").strip())

            bet = player.place_bet(amount, bet_type, bet_value)
            if bet is None:
                continue

            result = seed_manager.generate_random_number(seed_manager.nonce)
            color = roulette.color_of(result)
            print(f"The ball landed on {roulette.display_number(result)} ({color})")

            winnings = bet.payout(result, color)
            player.collect_winnings(winnings)
            print(f"Player won: {Fore.GREEN}${winnings}{Style.RESET_ALL}, New Balance: {Fore.YELLOW}${player.balance}{Style.RESET_ALL}")

            # Verificar la equidad con Provably Fair
            if seed_manager.verify_random_number(result, seed_manager.nonce):
                print("\n" + Fore.GREEN + "Provably Fair: The result has been verified!".center(79) + Style.RESET_ALL)
                print(Fore.GREEN + "-" * 79 + Style.RESET_ALL)
                print(" Server Seed: " + Fore.GREEN + f"{seed_manager.server_seed}" + Style.RESET_ALL)
                print(" Client Seed: " + Fore.GREEN + f"{seed_manager.client_seed}" + Style.RESET_ALL)
                print(" Nonce:       " + Fore.GREEN + f"{seed_manager.nonce}" + Style.RESET_ALL)
                print(Fore.GREEN + "-" * 79 + Style.RESET_ALL + "\n")

            else:
                print("\n" + Fore.RED + "Provably Fair: Error in verification." + Style.RESET_ALL)
                print(Fore.RED + "-" * 79 + Style.RESET_ALL)
                print(" Server Seed: " + Fore.RED + f"{seed_manager.server_seed}" + Style.RESET_ALL)
                print(" Client Seed: " + Fore.RED + f"{seed_manager.client_seed}" + Style.RESET_ALL)
                print(" Nonce:       " + Fore.RED + f"{seed_manager.nonce}" + Style.RESET_ALL)
                print(Fore.RED + "-" * 79 + Style.RESET_ALL)
                player.refund_bet(amount)
            seed_manager.nonce += 1

            if input("Play again? (y/n): ").strip().lower() not in ['y', 'yes']:
                print("\n\n" + Fore.RED + "Leaving the game, thank you for playing!" + Style.RESET_ALL)
                exit()

    except KeyboardInterrupt:
        print("\n\n" + Fore.RED + "Leaving the game, thank you for playing!" + Style.RESET_ALL)
        exit()

if __name__ == "__main__":
    main()
