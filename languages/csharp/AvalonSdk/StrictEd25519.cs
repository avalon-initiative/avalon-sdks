// Cofactorless Ed25519 verification with a canonical S and a byte-exact R, the same acceptance
// rule as the server's ed25519-dalek `verify`: [S]B - [k]A must encode to exactly the
// signature's R bytes and S must be below the group order. The BouncyCastle verifier accepts
// signatures whose R carries a torsion component, which the server rejects, so it is not used here.

using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Avalon.Sdk
{
    internal static class StrictEd25519
    {
        private static readonly BigInteger P = (BigInteger.One << 255) - 19;
        private static readonly BigInteger GroupOrder =
            (BigInteger.One << 252) + BigInteger.Parse("27742317777372353535851937790883648493");
        private static readonly BigInteger D = Mod(-121665 * ModInverse(121666));
        private static readonly BigInteger TwoD = Mod(2 * D);
        private static readonly BigInteger SqrtMinusOne = BigInteger.ModPow(2, (P - 1) / 4, P);
        private static readonly Point Identity = new Point(0, 1, 1, 0);
        private static readonly Point BasePoint = MakeBase();

        private readonly struct Point
        {
            public Point(BigInteger x, BigInteger y, BigInteger z, BigInteger t)
            {
                X = x;
                Y = y;
                Z = z;
                T = t;
            }

            public BigInteger X { get; }
            public BigInteger Y { get; }
            public BigInteger Z { get; }
            public BigInteger T { get; }
        }

        private static BigInteger Mod(BigInteger v)
        {
            var r = v % P;
            return r.Sign < 0 ? r + P : r;
        }

        private static BigInteger ModInverse(BigInteger v) => BigInteger.ModPow(Mod(v), P - 2, P);

        private static Point Affine(BigInteger x, BigInteger y) => new Point(x, y, 1, Mod(x * y));

        private static Point MakeBase()
        {
            var y = Mod(4 * ModInverse(5));
            return Affine(RecoverX(y, false)!.Value, y);
        }

        private static BigInteger? RecoverX(BigInteger y, bool signBit)
        {
            var x2 = Mod((y * y - 1) * ModInverse(D * y * y + 1));
            if (x2.IsZero)
            {
                return BigInteger.Zero;
            }
            var x = BigInteger.ModPow(x2, (P + 3) / 8, P);
            if (!Mod(x * x - x2).IsZero)
            {
                x = Mod(x * SqrtMinusOne);
            }
            if (!Mod(x * x - x2).IsZero)
            {
                return null;
            }
            return x.IsEven == signBit ? P - x : x;
        }

        private static Point Add(Point a, Point b)
        {
            var A = Mod((a.Y - a.X) * (b.Y - b.X));
            var B = Mod((a.Y + a.X) * (b.Y + b.X));
            var C = Mod(a.T * TwoD * b.T);
            var Dd = Mod(2 * a.Z * b.Z);
            var E = B - A;
            var F = Dd - C;
            var G = Dd + C;
            var H = B + A;
            return new Point(Mod(E * F), Mod(G * H), Mod(F * G), Mod(E * H));
        }

        private static Point Negate(Point a) => new Point(Mod(-a.X), a.Y, a.Z, Mod(-a.T));

        private static Point Multiply(BigInteger scalar, Point point)
        {
            var result = Identity;
            var addend = point;
            while (!scalar.IsZero)
            {
                if (!scalar.IsEven)
                {
                    result = Add(result, addend);
                }
                addend = Add(addend, addend);
                scalar >>= 1;
            }
            return result;
        }

        private static bool IsIdentity(Point a) => Mod(a.X).IsZero && Mod(a.Y - a.Z).IsZero;

        private static byte[] Encode(Point a)
        {
            var zInv = ModInverse(a.Z);
            var x = Mod(a.X * zInv);
            var y = Mod(a.Y * zInv);
            var bytes = new byte[32];
            var yBytes = y.ToByteArray();
            Array.Copy(yBytes, bytes, Math.Min(yBytes.Length, 32));
            if (!x.IsEven)
            {
                bytes[31] |= 0x80;
            }
            return bytes;
        }

        private static BigInteger LittleEndian(byte[] bytes, int offset, int length)
        {
            var buffer = new byte[length + 1];
            Array.Copy(bytes, offset, buffer, 0, length);
            return new BigInteger(buffer);
        }

        // Decompresses like dalek: y is reduced mod p when it is not below p, and x = 0 with the
        // sign bit set decodes to x = 0. Null when the encoding is not a curve point.
        private static Point? Decode(byte[] encoded)
        {
            if (encoded.Length != 32)
            {
                return null;
            }
            var signBit = (encoded[31] & 0x80) != 0;
            var masked = (byte[])encoded.Clone();
            masked[31] &= 0x7f;
            var y = Mod(LittleEndian(masked, 0, 32));
            var x = RecoverX(y, signBit);
            return x == null ? (Point?)null : Affine(x.Value, y);
        }

        /// <summary>Whether <paramref name="key"/> is acceptable as the key of a <c>node:</c>
        /// shard: a canonical encoding (y below 2^255-19, no sign bit on x = 0) of a curve point
        /// that is not of small order.</summary>
        internal static bool IsAcceptableShardKey(byte[] key)
        {
            if (key.Length != 32)
            {
                return false;
            }
            var masked = (byte[])key.Clone();
            masked[31] &= 0x7f;
            if (LittleEndian(masked, 0, 32) >= P)
            {
                return false;
            }
            var point = Decode(key);
            if (point == null)
            {
                return false;
            }
            if (Mod(point.Value.X).IsZero && (key[31] & 0x80) != 0)
            {
                return false;
            }
            return !IsIdentity(Multiply(8, point.Value));
        }

        /// <summary>Whether the 32-byte encoding decodes to a point of order 1, 2, 4 or 8.</summary>
        private static bool IsSmallOrderEncoding(byte[] encoded)
        {
            var point = Decode(encoded);
            return point != null && IsIdentity(Multiply(8, point.Value));
        }

        /// <summary><see cref="Verify"/> that also rejects a small-order key or a small-order R,
        /// like ed25519-dalek's <c>verify_strict</c>; what identity-bound signatures need.</summary>
        internal static bool VerifyStrict(byte[] publicKey, byte[] message, byte[] signature)
        {
            try
            {
                if (publicKey.Length != 32 || signature.Length != 64)
                {
                    return false;
                }
                var r = new byte[32];
                Array.Copy(signature, 0, r, 0, 32);
                return !IsSmallOrderEncoding(publicKey) && !IsSmallOrderEncoding(r) && Verify(publicKey, message, signature);
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>Cofactorless verification of a 64-byte <paramref name="signature"/> over
        /// <paramref name="message"/> under the 32-byte <paramref name="publicKey"/>; false for
        /// every failure, never throws.</summary>
        internal static bool Verify(byte[] publicKey, byte[] message, byte[] signature)
        {
            try
            {
                if (publicKey.Length != 32 || signature.Length != 64)
                {
                    return false;
                }
                var s = LittleEndian(signature, 32, 32);
                if (s >= GroupOrder)
                {
                    return false;
                }
                var a = Decode(publicKey);
                if (a == null)
                {
                    return false;
                }
                byte[] digest;
                using (var sha = SHA512.Create())
                {
                    var input = new byte[64 + message.Length];
                    Array.Copy(signature, 0, input, 0, 32);
                    Array.Copy(publicKey, 0, input, 32, 32);
                    Array.Copy(message, 0, input, 64, message.Length);
                    digest = sha.ComputeHash(input);
                }
                var k = LittleEndian(digest, 0, 64) % GroupOrder;
                var recomputed = Encode(Add(Multiply(s, BasePoint), Negate(Multiply(k, a.Value))));
                for (var i = 0; i < 32; i++)
                {
                    if (recomputed[i] != signature[i])
                    {
                        return false;
                    }
                }
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
