import random
import math

# ------------------------------------------------------------
# 1. Вспомогательные математические функции
# ------------------------------------------------------------

def is_prime_miller_rabin(n, k=40):
    """
    Вероятностный тест Миллера–Рабина на простоту.
    n  — проверяемое число
    k  — число итераций (вероятность ошибки <= 4^(-k))
    Возвращает True, если n, вероятно, простое.
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Представим n-1 как 2^r * d, где d нечётное
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # k раундов проверки
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)          # a^d mod n

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)      # x^2 mod n
            if x == n - 1:
                break
        else:
            return False          # составное число
    return True


def generate_large_prime(bits=512):
    """
    Генерирует случайное простое число заданной битовой длины.
    bits — желаемая длина числа в битах (по умолчанию 512).
    """
    while True:
        # Генерируем случайное нечётное число нужной длины
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1))   # устанавливаем старший бит
        candidate |= 1                    # делаем нечётным
        if is_prime_miller_rabin(candidate):
            return candidate


def extended_gcd(a, b):
    """
    Расширенный алгоритм Евклида.
    Возвращает (g, x, y) такие, что a*x + b*y = g = НОД(a, b).
    """
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y


def mod_inverse(e, phi):
    """
    Вычисляет модульный обратный элемент: e^(-1) mod phi.
    Используется расширенный алгоритм Евклида.
    Генерирует ValueError, если обратного элемента не существует.
    """
    g, x, _ = extended_gcd(e % phi, phi)
    if g != 1:
        raise ValueError('Обратный элемент не существует: НОД != 1')
    return x % phi


# ------------------------------------------------------------
# 2. Генерация ключей RSA
# ------------------------------------------------------------

def generate_rsa_keys(bits=512):
    """
    Генерирует пару ключей RSA.
    bits — размер каждого простого числа p и q (модуль n = 2*bits).
    Возвращает ((e, n), (d, n)) — (открытый_ключ, закрытый_ключ).
    """
    # Шаг 1: выбираем два различных простых числа
    print(f'[*] Генерация простых чисел p и q длиной {bits} бит...')
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)
    while q == p:
        q = generate_large_prime(bits)   # p и q должны различаться

    # Шаг 2: вычисляем модуль n
    n = p * q
    print(f'[*] n = p * q вычислен, длина модуля: {n.bit_length()} бит')

    # Шаг 3: вычисляем функцию Эйлера
    phi = (p - 1) * (q - 1)

    # Шаг 4: выбираем открытую экспоненту e
    # Стандартное значение e = 65537 (простое, эффективное)
    e = 65537
    if math.gcd(e, phi) != 1:
        # Если НОД(e, phi) != 1 — перебираем другое e
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2

    # Шаг 5: вычисляем секретную экспоненту d
    d = mod_inverse(e, phi)

    print(f'[*] Открытый ключ: e = {e}')
    print(f'[*] Ключевая пара успешно сгенерирована.')

    # p, q и phi должны уничтожаться после генерации ключей!
    return (e, n), (d, n)


# ------------------------------------------------------------
# 3. Шифрование и расшифровка
# ------------------------------------------------------------

def encrypt(message: str, public_key: tuple) -> list:
    """
    Шифрует строку message с помощью открытого ключа (e, n).
    Каждый символ шифруется отдельно (учебный режим).
    Возвращает список зашифрованных целых чисел.
    """
    e, n = public_key
    # Преобразуем каждый символ в его ASCII/Unicode-код и шифруем
    ciphertext = [pow(ord(char), e, n) for char in message]
    return ciphertext


def decrypt(ciphertext: list, private_key: tuple) -> str:
    """
    Расшифровывает список зашифрованных чисел с помощью
    закрытого ключа (d, n).
    Возвращает исходную строку.
    """
    d, n = private_key
    # Для каждого числа: M = C^d mod n, затем chr(M)
    plaintext = ''.join([chr(pow(c, d, n)) for c in ciphertext])
    return plaintext


# ------------------------------------------------------------
# 4. Демонстрация работы
# ------------------------------------------------------------

if __name__ == '__main__':
    print('=' * 60)
    print('  Демонстрация алгоритма RSA')
    print('=' * 60)

    # Генерация ключей (512-битные простые числа = 1024-битный модуль)
    public_key, private_key = generate_rsa_keys(bits=512)
    e, n = public_key
    d, _ = private_key

    # Исходное сообщение
    message = 'RSA Cryptography!'
    print(f'\nИсходное сообщение : {message}')

    # Шифрование
    ciphertext = encrypt(message, public_key)
    print(f'Зашифрованный текст: {ciphertext[:3]}... (показаны первые 3 числа)')

    # Расшифровка
    decrypted = decrypt(ciphertext, private_key)
    print(f'Расшифрованный текст: {decrypted}')

    # Проверка корректности
    assert message == decrypted, 'ОШИБКА: сообщения не совпадают!'
    print('\n[OK] Шифрование и расшифровка выполнены успешно!')
    print('=' * 60)
