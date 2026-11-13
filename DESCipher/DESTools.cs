using System;
using System.Collections.Generic;
using System.Text;

namespace DESCipher;

public static class DESTools
{
    public static byte[] Encrypt(byte[] rawData, byte[] key)
    {
        bool[][] roundKeys = GenerateRoundKeys(key);
        EnsureKeyIsStrong(roundKeys);
        byte[] data = AddPadding(rawData);
        byte[] result = new byte[data.Length];

        for (int offset = 0; offset < data.Length; offset += 8)
        {
            byte[] block = data[offset..(offset + 8)];
            byte[] encrypted = EncryptBlock(block, roundKeys);
            Array.Copy(encrypted, 0, result, offset, 8);
        }

        return result;
    }

    public static byte[] Decrypt(byte[] encryptedData, byte[] key)
    {
        if (encryptedData.Length == 0 || encryptedData.Length % 8 != 0)
            throw new ArgumentException("Encrypted data length must be a non-zero multiple of 8");

        bool[][] roundKeys = GenerateRoundKeys(key);
        EnsureKeyIsStrong(roundKeys);
        byte[] result = new byte[encryptedData.Length];

        for (int offset = 0; offset < encryptedData.Length; offset += 8)
        {
            byte[] block = encryptedData[offset..(offset + 8)];
            byte[] decrypted = DecryptBlock(block, roundKeys);
            Array.Copy(decrypted, 0, result, offset, 8);
        }

        return RemovePadding(result);
    }

    private static byte[] EncryptBlock(byte[] block, bool[][] roundKeys) => ProcessBlock(block, roundKeys);
    private static byte[] DecryptBlock(byte[] block, bool[][] roundKeys) => ProcessBlock(block, roundKeys.Reverse().ToArray());

    private static byte[] ProcessBlock(byte[] block, bool[][] roundKeys, List<bool[]>? trace = null)
    {
        if (block.Length != 8)
            throw new ArgumentException($"The block {Convert.ToHexString(block)} is not 64 bits long");

        bool[] blockBits = BytesToBits(block);
        bool[] permutedBlock = Permute(blockBits, DESTables.IP);

        bool[] l = permutedBlock[..32];
        bool[] r = permutedBlock[32..];

        trace?.Add(l.Concat(r).ToArray());

        for (int i = 0; i < 16; i++)
        {
            bool[] newR = Xor(l, F(r, roundKeys[i]));
            l = r;
            r = newR;
            trace?.Add(l.Concat(r).ToArray());
        }

        bool[] mixedBlock = r.Concat(l).ToArray();
        bool[] permutedEncryptedBlock = Permute(mixedBlock, DESTables.FP);

        return BitsToBytes(permutedEncryptedBlock);
    }

    private static bool[] SBoxes(bool[] input48)
    {
        bool[] output = new bool[32];

        for (int i = 0; i < 8; i++)
        {
            bool[] part = input48[(i * 6)..(i * 6 + 6)];
            int row = BitsToInt(new bool[] { part[0], part[^1] });
            int col = BitsToInt(part[1..^1]);
            int value = DESTables.S[i, row, col];

            for (int b = 0; b < 4; b++)
                output[i * 4 + b] = ((value >> (3 - b)) & 1) == 1;
        }

        return output;
    }

    private static bool[] F(bool[] right, bool[] roundKey)
    {
        bool[] expanded = Permute(right, DESTables.E);
        bool[] mixed = Xor(expanded, roundKey);
        bool[] sOut = SBoxes(mixed);
        return Permute(sOut, DESTables.P);
    }

    private static bool[][] GenerateRoundKeys(byte[] key)
    {
        bool[][] roundKeys = new bool[DESTables.Shifts.Length][];
        bool[] key56 = PermutedChoice_1(key);

        bool[] c = key56[..28];
        bool[] d = key56[28..];

        for (int i = 0; i < 16; i++)
        {
            c = ApplyShift(c, i);
            d = ApplyShift(d, i);
            roundKeys[i] = PermutedChoice_2(c.Concat(d).ToArray());
        }

        return roundKeys;
    }

    private static bool[] ApplyShift(bool[] part, int round)
    {
        if (round < 0 || round >= DESTables.Shifts.Length)
            throw new ArgumentOutOfRangeException(nameof(round), $"Incorrect round number: {round}");

        int shift = DESTables.Shifts[round];
        return part[shift..].Concat(part[..shift]).ToArray();
    }

    private static bool[] PermutedChoice_1(byte[] key)
    {
        if (key.Length != 8)
            throw new ArgumentException($"The key {Convert.ToHexString(key)} is not 64 bits long");

        bool[] bitKey = BytesToBits(key);
        int[] pc1 = DESTables.PC1;

        bool[] permutedKey = Permute(bitKey, pc1);

        return permutedKey;
    }

    private static bool[] PermutedChoice_2(bool[] key)
    {
        if (key.Length != 56)
            throw new ArgumentException($"The key is not 56 bits long");

        int[] pc2 = DESTables.PC2;

        bool[] permutedKey = Permute(key, pc2);

        return permutedKey;
    }

    private static bool[] Permute(bool[] input, int[] table)
    {
        bool[] output = new bool[table.Length];
        for (int i = 0; i < table.Length; i++)
            output[i] = input[table[i] - 1];
        return output;
    }

    private static bool[] BytesToBits(byte[] bytes)
    {
        bool[] bits = new bool[bytes.Length * 8];

        for (int i = 0; i < bytes.Length; i++)
        {
            for (int b = 0; b < 8; b++)
            {
                bits[i * 8 + b] = ((bytes[i] >> (7 - b)) & 1) == 1;
            }
        }

        return bits;
    }

    private static byte[] BitsToBytes(bool[] bits)
    {
        if (bits.Length % 8 != 0)
            throw new ArgumentException("Bits count must be a multiple of 8");

        byte[] bytes = new byte[bits.Length / 8];

        for (int i = 0; i < bytes.Length; i++)
        {
            for (int b = 0; b < 8; b++)
            {
                if (bits[i * 8 + b])
                    bytes[i] |= (byte)(1 << (7 - b));
            }
        }

        return bytes;
    }

    private static bool[] Xor(bool[] a, bool[] b)
    {
        if (a.Length != b.Length)
            throw new ArgumentException("a and b must be equal to XOR");

        int len = a.Length;

        bool[] result = new bool[len];

        for (int i = 0; i < len; i++)
        {
            result[i] = a[i] != b[i];
        }

        return result;
    }

    private static int BitsToInt(bool[] bits)
    {
        int len = bits.Length;
        int res = 0;
        for (int i = 1; i <= len; i++)
        {
            if (bits[^i]) res += 1 << (i - 1);
        }
        return res;
    }

    private static byte[] AddPadding(byte[] data)
    {
        int padLength = 8 - data.Length % 8;
        byte[] result = new byte[data.Length + padLength];

        Array.Copy(data, result, data.Length);
        for (int i = data.Length; i < result.Length; i++)
            result[i] = (byte)padLength;

        return result;
    }

    private static byte[] RemovePadding(byte[] data)
    {
        int padLength = data[^1];

        if (padLength < 1 || padLength > 8)
            throw new ArgumentException("Wrong key or corrupted data");

        for (int i = 1; i <= padLength; i++)
            if (data[^i] != padLength)
                throw new ArgumentException("Wrong key or corrupted data");

        return data[..^padLength];
    }

    // Checks

    public static bool IsWeakKey(byte[] key) => CountDistinctRoundKeys(GenerateRoundKeys(key)) == 1;

    public static bool IsSemiWeakKey(byte[] key) => CountDistinctRoundKeys(GenerateRoundKeys(key)) == 2;

    private static int CountDistinctRoundKeys(bool[][] roundKeys)
    {
        var unique = new HashSet<string>();
        foreach (bool[] k in roundKeys)
            unique.Add(string.Concat(k.Select(b => b ? '1' : '0')));
        return unique.Count;
    }

    private static void EnsureKeyIsStrong(bool[][] roundKeys)
    {
        int distinct = CountDistinctRoundKeys(roundKeys);
        if (distinct == 1)
            throw new ArgumentException("Weak key: all 16 round keys are identical");
        if (distinct == 2)
            throw new ArgumentException("Semi-weak key: only 2 different round keys");
    }

    public static double[] CalculateRoundEntropy(byte[] rawData, byte[] key)
    {
        bool[][] roundKeys = GenerateRoundKeys(key);
        byte[] data = AddPadding(rawData);

        var stateBytes = new List<byte>[17];
        for (int i = 0; i < 17; i++)
            stateBytes[i] = new List<byte>();

        for (int offset = 0; offset < data.Length; offset += 8)
        {
            var trace = new List<bool[]>();
            ProcessBlock(data[offset..(offset + 8)], roundKeys, trace);

            for (int i = 0; i < 17; i++)
                stateBytes[i].AddRange(BitsToBytes(trace[i]));
        }

        double[] entropy = new double[17];
        for (int i = 0; i < 17; i++)
            entropy[i] = Entropy(stateBytes[i].ToArray());

        return entropy;
    }

    public static double Entropy(byte[] data)
    {
        int[] counts = new int[256];
        foreach (byte b in data)
            counts[b]++;

        double h = 0;
        foreach (int count in counts)
        {
            if (count == 0) continue;
            double p = (double)count / data.Length;
            h -= p * Math.Log2(p);
        }
        return h;
    }
}
