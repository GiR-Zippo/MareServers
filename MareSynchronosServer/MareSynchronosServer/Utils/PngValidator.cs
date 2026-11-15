using System.Buffers.Binary;
using System.IO.Hashing;

namespace MareSynchronosServer.Utils;

public static class PngValidator
{
    private static ReadOnlySpan<byte> Signature => [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    /// <summary>Checks PNG-Structure (Signature, Chunk-Length, CRCs, IHDR/IDAT/IEND), without pixel decoding.</summary>
    public static bool TryRead(byte[] data, out int width, out int height)
    {
        width = height = 0;
        if (data.Length < 8 + 25 || !data.AsSpan(0, 8).SequenceEqual(Signature)) return false;

        int pos = 8;
        bool first = true, sawIdat = false, sawIend = false;

        while (pos + 12 <= data.Length)
        {
            uint len = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(pos, 4));
            if (len > int.MaxValue || pos + 12L + len > data.Length) return false;

            var type = data.AsSpan(pos + 4, 4);
            uint expectedCrc = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(pos + 8 + (int)len, 4));
            if (Crc32.HashToUInt32(data.AsSpan(pos + 4, (int)len + 4)) != expectedCrc) return false;

            if (first)
            {
                if (!type.SequenceEqual("IHDR"u8) || len != 13) return false;
                width = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(pos + 8, 4));
                height = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(pos + 12, 4));
                if (width <= 0 || height <= 0) return false;
                first = false;
            }
            else if (type.SequenceEqual("IDAT"u8)) sawIdat = true;
            else if (type.SequenceEqual("IEND"u8)) { sawIend = true; break; }

            pos += 12 + (int)len;
        }

        return !first && sawIdat && sawIend;
    }
}