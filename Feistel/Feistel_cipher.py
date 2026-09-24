import random

# ============================================================
# S-Box из PRESENT
# ============================================================
S_BOX = {
    "0000": "1100", "0001": "0101", "0010": "0110", "0011": "1011",
    "0100": "1001", "0101": "0000", "0110": "1010", "0111": "1101",
    "1000": "0011", "1001": "1010", "1010": "0110", "1011": "1100",
    "1100": "0101", "1101": "1001", "1110": "0000", "1111": "0111",
}

BLOCK_SIZE = 64
NUM_ROUNDS = 16


# ============================================================
# Вспомогательные операции
# ============================================================
def xor_bits(a, b):
    return "".join("0" if a[i] == b[i] else "1" for i in range(len(a)))


def rotl(bits, n):
    n = n % len(bits)
    return bits[n:] + bits[:n]


def sbox_16(x):
    return "".join(S_BOX[x[i:i+4]] for i in range(0, 16, 4))


def F(x, k):
    """Раундовая функция: F(x, k) = S(x XOR k). Необратима."""
    return sbox_16(xor_bits(x, k))


# ============================================================
# Key schedule: 16 подключей по 16 бит из ключа >= 128 бит
# Гибко к длине: остаток ключа паддится до 16 и XOR-ится по кругу.
# ============================================================
def key_schedule(master_key):
    if len(master_key) < 128:
        raise ValueError("Ключ должен быть не менее 128 бит.")

    K = [master_key[i:i+16] for i in range(0, 128, 16)]

    rest = master_key[128:]
    if rest:
        # Дополняем остаток нулями до кратности 16
        if len(rest) % 16 != 0:
            rest = rest.ljust((len(rest) // 16 + 1) * 16, "0")
        for i in range(0, len(rest), 16):
            idx = (i // 16) % 8
            K[idx] = xor_bits(K[idx], rest[i:i+16])

    subkeys = []
    for r in range(1, NUM_ROUNDS + 1):
        subkey = xor_bits(K[r % 8], format(r, "016b"))
        subkeys.append(subkey)
        new_K = []
        for i in range(8):
            new_K.append(xor_bits(K[i], rotl(K[(i+1) % 8], r + 1)))
        K = new_K
    return subkeys


# ============================================================
# Сеть Фейстеля (Type-2 GFN, 4 ветви)
# ============================================================
def feistel_encrypt_block(block, subkeys, verbose=False):
    A, B, C, D = block[0:16], block[16:32], block[32:48], block[48:64]

    if verbose:
        print("\n--- РАУНД 1 (подробно, шифрование) ---")
        print(f"A={A} B={B} C={C} D={D}")
        print("Подключ K1:", subkeys[0])

    for r, k in enumerate(subkeys):
        t = xor_bits(A, F(B, k))
        if verbose and r == 0:
            print(f"F(B,K1) = {F(B, k)}")
            print(f"new_D = A XOR F(B,K1) = {t}")
        A, B, C, D = B, C, D, t
        if verbose and r == 0:
            print(f"После раунда: A={A} B={B} C={C} D={D}")

    return A + B + C + D


def feistel_decrypt_block(block, subkeys, verbose=False):
    A, B, C, D = block[0:16], block[16:32], block[32:48], block[48:64]

    if verbose:
        print("\n--- РАУНД 1 (подробно, расшифрование) ---")
        print(f"A={A} B={B} C={C} D={D}")
        print("Подключ:", subkeys[-1])

    for r, k in enumerate(reversed(subkeys)):
        t = xor_bits(D, F(A, k))
        if verbose and r == 0:
            print(f"F(A,K) = {F(A, k)}")
            print(f"new_A = D XOR F(A,K) = {t}")
        A, B, C, D = t, A, B, C
        if verbose and r == 0:
            print(f"После раунда: A={A} B={B} C={C} D={D}")

    return A + B + C + D


# ============================================================
# Разбиение на блоки
# ============================================================
def split_blocks(bits):
    blocks = []
    for i in range(0, len(bits), BLOCK_SIZE):
        b = bits[i:i+BLOCK_SIZE]
        if len(b) < BLOCK_SIZE:
            b = b.ljust(BLOCK_SIZE, "0")
        blocks.append(b)
    return blocks


# ============================================================
# Режим CFB-64
# ============================================================
def cfb_encrypt(message, subkeys, iv):
    blocks = split_blocks(message)
    prev = iv
    ciphertext = ""
    for i, p in enumerate(blocks):
        keystream = feistel_encrypt_block(prev, subkeys, verbose=(i == 0))
        c = xor_bits(p, keystream)
        ciphertext += c
        prev = c
    return ciphertext


def cfb_decrypt(ciphertext, subkeys, iv):
    blocks = split_blocks(ciphertext)
    prev = iv
    plaintext = ""
    for i, c in enumerate(blocks):
        keystream = feistel_encrypt_block(prev, subkeys, verbose=(i == 0))
        p = xor_bits(c, keystream)
        plaintext += p
        prev = c
    return plaintext


# ============================================================
# Hex <-> Bits
# ============================================================
def hex_to_bits(h):
    h = h.replace(" ", "").replace("\n", "").lower()
    if not h or any(c not in "0123456789abcdef" for c in h):
        raise ValueError("Некорректная hex-строка.")
    return "".join(format(int(c, 16), "04b") for c in h)


def bits_to_hex(b):
    if len(b) % 4 != 0:
        b = b.ljust((len(b) // 4 + 1) * 4, "0")
    return "".join(format(int(b[i:i+4], 2), "x") for i in range(0, len(b), 4))


def random_iv():
    return "".join(random.choice("01") for _ in range(BLOCK_SIZE))


# ============================================================
# Ввод BIN
# ============================================================
def input_bin_bits(prompt, min_bits):
    while True:
        v = input(prompt).replace(" ", "").replace("\n", "")
        if not v:
            print("Ошибка: пусто.")
            continue
        if any(c not in "01" for c in v):
            print("Ошибка: только 0 и 1.")
            continue
        if len(v) < min_bits:
            print(f"Ошибка: нужно ≥ {min_bits} бит (сейчас {len(v)}).")
            continue
        return v


# ============================================================
# Ввод HEX
# ============================================================
def input_hex_bits(prompt, min_hex_chars):
    while True:
        v = input(prompt).replace(" ", "").replace("\n", "")
        if not v:
            print("Ошибка: пусто.")
            continue
        try:
            bits = hex_to_bits(v)
        except ValueError as e:
            print(f"Ошибка: {e}")
            continue
        if len(v) < min_hex_chars:
            print(f"Ошибка: нужно ≥ {min_hex_chars} hex-символов "
                  f"(сейчас {len(v)}, это {len(bits)} бит).")
            continue
        return bits


def input_iv_hex():
    while True:
        v = input("IV (hex, ровно 16 символов = 64 бита):\n").strip()
        try:
            iv = hex_to_bits(v)
        except ValueError as e:
            print(f"Ошибка IV: {e}")
            continue
        if len(iv) != BLOCK_SIZE:
            print(f"Ошибка: IV должен быть ровно {BLOCK_SIZE} бит "
                  f"({BLOCK_SIZE // 4} hex-символов).")
            continue
        return iv


def input_iv_bin():
    while True:
        v = input("IV (bin, ровно 64 символа):\n").replace(" ", "").replace("\n", "")
        if any(c not in "01" for c in v) or len(v) != BLOCK_SIZE:
            print(f"Ошибка: IV должен быть ровно {BLOCK_SIZE} бит из 0 и 1.")
            continue
        return v


# ============================================================
# Меню
# ============================================================
def main():
    use_hex = True

    while True:
        fmt = "HEX" if use_hex else "BIN"
        print("\n" + "=" * 60)
        print("  Сеть Фейстеля (Type-2 GFN, 4 ветви) + CFB-64")
        print(f"  Формат ввода: {fmt}")
        print("=" * 60)
        print("1. Зашифровать")
        print("2. Расшифровать")
        print("3. Переключить формат (HEX/BIN)")
        print("4. Выйти")
        choice = input("Выбор: ")

        if choice == "1":
            if use_hex:
                msg = input_hex_bits(
                    "Сообщение (hex, ≥ 64 символа = 256 бит):\n", 64
                )
                key = input_hex_bits(
                    "Ключ (hex, ≥ 32 символа = 128 бит, любой длины):\n", 32
                )
            else:
                msg = input_bin_bits(
                    "Сообщение (bin, ≥ 256 бит):\n", 256
                )
                key = input_bin_bits(
                    "Ключ (bin, ≥ 128 бит, любой длины):\n", 128
                )

            subkeys = key_schedule(key)
            iv = random_iv()

            ct = cfb_encrypt(msg, subkeys, iv)

            n_blocks = len(split_blocks(msg))
            print("\n" + "=" * 60)
            print("ШИФРОТЕКСТ")
            print("=" * 60)
            if use_hex:
                print("HEX:", bits_to_hex(ct))
                print("IV  (hex):", bits_to_hex(iv))
            else:
                print("BIN:", ct)
                print("IV  (bin):", iv)
            print(f"\nБлоков: {n_blocks}, раундов на блок: {NUM_ROUNDS}, "
                  f"всего раундов: {n_blocks * NUM_ROUNDS}")
            print(f"Длина сообщения: {len(msg)} бит, "
                  f"шифротекста: {len(ct)} бит")
            print("=" * 60)

        elif choice == "2":
            if use_hex:
                ct = input_hex_bits(
                    "Шифротекст (hex, ≥ 64 символа):\n", 64
                )
                key = input_hex_bits(
                    "Ключ (hex, ≥ 32 символа):\n", 32
                )
                iv = input_iv_hex()
            else:
                ct = input_bin_bits(
                    "Шифротекст (bin, ≥ 256 бит):\n", 256
                )
                key = input_bin_bits(
                    "Ключ (bin, ≥ 128 бит):\n", 128
                )
                iv = input_iv_bin()

            subkeys = key_schedule(key)
            pt = cfb_decrypt(ct, subkeys, iv)

            print("\n" + "=" * 60)
            print("РАСШИФРОВАННОЕ СООБЩЕНИЕ")
            print("=" * 60)
            if use_hex:
                print("HEX:", bits_to_hex(pt))
            else:
                print("BIN:", pt)
            print(f"Длина: {len(pt)} бит")
            print("=" * 60)

        elif choice == "3":
            use_hex = not use_hex
            print(f"\nФормат переключён на {'HEX' if use_hex else 'BIN'}.")

        elif choice == "4":
            print("Выход.")
            break


main()