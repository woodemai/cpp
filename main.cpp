#include <iostream>
#include <fstream>
#include <cstdint>
#include <vector>
#include <random>
#include <bitset>

constexpr size_t BLOCK_SIZE = 64;    // Размер шифруемых блоков
constexpr size_t SUBBLOCK_SIZE = 32; // Размер сабблоков L и R
constexpr size_t KEY_SIZE = 64;      // Размер ключа
constexpr size_t NUM_ROUNDS = 8;     // Количество циклов шифрования

using namespace std;

string pad_input_text(const string& input_text)
{
    string padded_text = input_text;
    size_t padding_size = 8 - (input_text.size() % 8);
    if (padding_size != 8)
    {
        padded_text += string(padding_size, '\ ');
    }
    return padded_text;
}

// Генерация случайно 64битного ключа
uint64_t get_random_key()
{
    random_device rd;
    mt19937_64 eng(rd());
    uniform_int_distribution<uint64_t> distr;
    return distr(eng);
}

// Цикличный сдвиг  вправо
uint32_t circular_right_shift(uint64_t key, unsigned n)
{
    return (key >> n) | (key << (KEY_SIZE - n));
}

// Цикличный сдвиг  влево
uint32_t circular_left_shift(uint32_t block, unsigned n)
{
    return (block << n) | (block >> (SUBBLOCK_SIZE - n));
}

// Функций округления
uint32_t round_function(uint32_t L, uint32_t K)
{
    return circular_left_shift(L, 9) ^ (~((circular_right_shift(K, 11) & L)));
}
// Шифрование
uint64_t feistel_encrypt(uint64_t block, uint64_t key)
{
    uint32_t L = block >> 32;
    uint32_t R = block & 0xFFFFFFFF;

    for (size_t i = 0; i < NUM_ROUNDS; ++i)
    {
        uint32_t K = circular_right_shift(key, i * 3) & 0xFFFFFFFF;
        uint32_t temp = R;
        R = L ^ round_function(R, K);
        L = temp;
    }

    return (uint64_t(R) << 32) | L;
}
// Дешифрование
uint64_t feistel_decrypt(uint64_t block, uint64_t key)
{
    uint32_t L = block & 0xFFFFFFFF;
    uint32_t R = block >> 32;

    for (int i = NUM_ROUNDS - 1; i >= 0; --i)
    {
        uint32_t K = circular_right_shift(key, i * 3) & 0xFFFFFFFF;
        uint32_t temp = L;
        L = R ^ round_function(L, K);
        R = temp;
    }

    return (uint64_t(L) << 32) | R;
}

// Вывод 64битного сообщения как текст в консоль
void print_block_to_console(const string &prefix, uint64_t block)
{
    cout << prefix;
    for (int i = 0; i < 8; ++i)
    {
        char c = (block >> (8 * i)) & 0xFF;
        if (c >= 32 && c <= 126) // Printable characters in ASCII
            cout << c;
        else
            cout << ".";
    }
    cout << endl;
}

// Чтение из файла, шифрование и вывод результата в консоль
void encrypt(const string &input_filename, const string &output_filename, uint64_t key)
{
    ifstream input_file(input_filename, ios::binary);  // Открытие файла в текстовом режиме
    ofstream output_file(output_filename, ios::binary);  // Открытие файла в бинарном режиме

    // Чтение входного текста из файла
    string input_text((istreambuf_iterator<char>(input_file)), (istreambuf_iterator<char>()));
    // Дополнение текста пустыми символами, если необходимо
    string padded_text = pad_input_text(input_text);

    // Шифрование и запись в выходной файл
    for (size_t i = 0; i < padded_text.size(); i += 8)
    {
        uint64_t block = 0;
        for (size_t j = 0; j < 8 && i + j < padded_text.size(); ++j)
        {
            block |= static_cast<uint64_t>(padded_text[i + j]) << (8 * j);
        }

        print_block_to_console("Encrypting block: ", block);
        uint64_t encrypted_block = feistel_encrypt(block, key);
        print_block_to_console("Encrypted block: ", encrypted_block);
        output_file.write(reinterpret_cast<char *>(&encrypted_block), sizeof(encrypted_block));
    }

    input_file.close();
    output_file.close();
}

// Чтение из файла, дешифрование и вывод результата в консоль
void decrypt(const string &input_filename, const string &output_filename, uint64_t key)
{
    ifstream input_file(input_filename, ios::binary);
    ofstream output_file(output_filename, ios::binary);

    uint64_t block;
    while (input_file.read(reinterpret_cast<char *>(&block), sizeof(block)))
    {
        print_block_to_console("Decrypting block: ", block);
        uint64_t decrypted_block = feistel_decrypt(block, key);
        print_block_to_console("Decrypted block: ", decrypted_block);
        output_file.write(reinterpret_cast<char *>(&decrypted_block), sizeof(decrypted_block));
    }

    input_file.close();
    output_file.close();
}

int main()
{
    uint64_t key = get_random_key();
    string input_filename = "input.bin";
    string encrypted_filename = "encrypted.bin";
    string decrypted_filename = "decrypted.bin";

    encrypt(input_filename, encrypted_filename, key);
    decrypt(encrypted_filename, decrypted_filename, key);

    return 0;
}