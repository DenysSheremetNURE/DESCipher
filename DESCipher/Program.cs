using System.Text;
using DESCipher;

Console.OutputEncoding = Encoding.UTF8;

Console.Write("Text: ");
string text = Console.ReadLine() ?? "";

Console.Write("Key (8 symbols): ");
string keyText = Console.ReadLine() ?? "";
byte[] key = Encoding.ASCII.GetBytes(keyText);

byte[] encrypted = DESTools.Encrypt(Encoding.UTF8.GetBytes(text), key);
Console.WriteLine($"Encrypted (hex): {Convert.ToHexString(encrypted)}");

byte[] decrypted = DESTools.Decrypt(encrypted, key);
Console.WriteLine($"Decrypted:      {Encoding.UTF8.GetString(decrypted)}");