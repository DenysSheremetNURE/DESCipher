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
Console.WriteLine($"Decrypted: {Encoding.UTF8.GetString(decrypted)}");

Console.WriteLine(DESTools.IsWeakKey(Convert.FromHexString("0101010101010101")));     // True
Console.WriteLine(DESTools.IsSemiWeakKey(Convert.FromHexString("01FE01FE01FE01FE"))); // True
Console.WriteLine(DESTools.IsWeakKey(Encoding.ASCII.GetBytes("secret12")));           // False

double[] h = DESTools.CalculateRoundEntropy(Encoding.UTF8.GetBytes(text), key);
for (int i = 0; i < h.Length; i++)
    Console.WriteLine($"Round {i,2}: {h[i]:F3}");