// Canonical encoding of free-form payloads: RFC 8785 restricted so every SDK reproduces it byte for byte. Mirrors
// crates/protocol/src/canonical_payload.rs; conformance/vectors/canonical-payload.json is the shared arbiter.
// A number is valid only if its text is an integer within +/-2^53 or a non-integral decimal of at most 15
// significant digits written exactly as ECMAScript prints it; duplicate keys are rejected; U+0000 is rejected in
// every string and key. A string may hold any Unicode scalar value except U+0000; U+0001..U+001F are valid only as
// escapes and lone surrogates are malformed.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;

namespace Avalon.Sdk
{
    /// <summary>Why a payload is not canonicalizable.</summary>
    public enum CanonicalPayloadError
    {
        /// <summary>A number that is not an exactly representable double; use a string.</summary>
        InvalidNumber,
        /// <summary>An object with the same key twice (compared after unescaping).</summary>
        DuplicateKey,
        /// <summary>A string or object key containing U+0000 (a raw NUL byte is <see cref="Malformed"/>).</summary>
        NulCharacter,
        /// <summary>Not JSON, or JSON outside the strict grammar.</summary>
        Malformed,
        /// <summary>Nesting deeper than <see cref="CanonicalPayload.MaxDepth"/>.</summary>
        TooDeep,
    }

    /// <summary>A payload the canonical encoder rejects; <see cref="Error"/> is the stable reason.</summary>
    public sealed class CanonicalPayloadException : Exception
    {
        public CanonicalPayloadException(CanonicalPayloadError error, string detail)
            : base(detail)
        {
            Error = error;
        }

        public CanonicalPayloadError Error { get; }
    }

    /// <summary>The restricted RFC 8785 encoder and strict parser.</summary>
    public static class CanonicalPayload
    {
        public const long MaxSafeInteger = 1L << 53;
        public const int MaxSignificantDigits = 15;
        public const int MaxDepth = 128;

        /// <summary>Parses <paramref name="json"/> strictly and returns its canonical text.</summary>
        public static string Canonicalize(string json)
        {
            var sb = new StringBuilder();
            Write(new Parser(json).ParseDocument(), sb);
            return sb.ToString();
        }

        /// <summary>The canonical text of an already-parsed document, re-read from its raw text so number
        /// spelling and duplicate keys are judged as written.</summary>
        public static string Canonicalize(JsonElement value) => Canonicalize(value.GetRawText());

        /// <summary>The canonical text as UTF-8 bytes.</summary>
        public static byte[] CanonicalizeToBytes(string json) => new UTF8Encoding(false).GetBytes(Canonicalize(json));

        /// <summary>Throws <see cref="CanonicalPayloadException"/> unless <paramref name="json"/> is canonicalizable.</summary>
        public static void Validate(string json) => new Parser(json).ParseDocument();

        private abstract class Node
        {
        }

        private sealed class Literal : Node
        {
            public Literal(string text)
            {
                Text = text;
            }

            public string Text { get; }
        }

        private sealed class Str : Node
        {
            public Str(string value)
            {
                Value = value;
            }

            public string Value { get; }
        }

        private sealed class Arr : Node
        {
            public List<Node> Items { get; } = new List<Node>();
        }

        private sealed class Obj : Node
        {
            public List<KeyValuePair<string, Node>> Entries { get; } = new List<KeyValuePair<string, Node>>();
        }

        private static void Write(Node node, StringBuilder sb)
        {
            switch (node)
            {
                case Literal l:
                    sb.Append(l.Text);
                    break;
                case Str s:
                    WriteString(s.Value, sb);
                    break;
                case Arr a:
                    sb.Append('[');
                    for (var i = 0; i < a.Items.Count; i++)
                    {
                        if (i > 0)
                        {
                            sb.Append(',');
                        }
                        Write(a.Items[i], sb);
                    }
                    sb.Append(']');
                    break;
                case Obj o:
                    var entries = new List<KeyValuePair<string, Node>>(o.Entries);
                    entries.Sort((x, y) => string.CompareOrdinal(x.Key, y.Key));
                    sb.Append('{');
                    for (var i = 0; i < entries.Count; i++)
                    {
                        if (i > 0)
                        {
                            sb.Append(',');
                        }
                        WriteString(entries[i].Key, sb);
                        sb.Append(':');
                        Write(entries[i].Value, sb);
                    }
                    sb.Append('}');
                    break;
            }
        }

        private static void WriteString(string s, StringBuilder sb)
        {
            sb.Append('"');
            foreach (var c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\t': sb.Append("\\t"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\r': sb.Append("\\r"); break;
                    default:
                        if (c < 0x20)
                        {
                            sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        }
                        else
                        {
                            sb.Append(c);
                        }
                        break;
                }
            }
            sb.Append('"');
        }

        private sealed class Parser
        {
            private readonly string _text;
            private int _pos;

            public Parser(string text)
            {
                _text = text ?? throw new ArgumentNullException(nameof(text));
            }

            private CanonicalPayloadException Malformed(string what) =>
                new CanonicalPayloadException(CanonicalPayloadError.Malformed, what + " at index " + _pos);

            public Node ParseDocument()
            {
                SkipWs();
                var value = Value(0);
                SkipWs();
                if (_pos != _text.Length)
                {
                    throw Malformed("trailing characters");
                }
                return value;
            }

            private void SkipWs()
            {
                while (_pos < _text.Length && (_text[_pos] == ' ' || _text[_pos] == '\t' || _text[_pos] == '\n' || _text[_pos] == '\r'))
                {
                    _pos++;
                }
            }

            private bool Eat(string literal)
            {
                if (_pos + literal.Length <= _text.Length && string.CompareOrdinal(_text, _pos, literal, 0, literal.Length) == 0)
                {
                    _pos += literal.Length;
                    return true;
                }
                return false;
            }

            private char Peek() => _pos < _text.Length ? _text[_pos] : '\0';

            private bool AtEnd => _pos >= _text.Length;

            private Node Value(int depth)
            {
                if (depth > MaxDepth)
                {
                    throw new CanonicalPayloadException(CanonicalPayloadError.TooDeep, "payload nests deeper than " + MaxDepth + " levels");
                }
                if (AtEnd)
                {
                    throw Malformed("unexpected token");
                }
                var c = _text[_pos];
                if (c == '{')
                {
                    return Object(depth);
                }
                if (c == '[')
                {
                    return Array(depth);
                }
                if (c == '"')
                {
                    return new Str(String());
                }
                if (c == 't' && Eat("true"))
                {
                    return new Literal("true");
                }
                if (c == 'f' && Eat("false"))
                {
                    return new Literal("false");
                }
                if (c == 'n' && Eat("null"))
                {
                    return new Literal("null");
                }
                if (c == '-' || (c >= '0' && c <= '9'))
                {
                    return Number();
                }
                throw Malformed("unexpected token");
            }

            private Node Object(int depth)
            {
                _pos++;
                var obj = new Obj();
                var seen = new HashSet<string>(StringComparer.Ordinal);
                SkipWs();
                if (Eat("}"))
                {
                    return obj;
                }
                while (true)
                {
                    SkipWs();
                    if (Peek() != '"')
                    {
                        throw Malformed("expected object key");
                    }
                    var key = String();
                    SkipWs();
                    if (!Eat(":"))
                    {
                        throw Malformed("expected `:`");
                    }
                    SkipWs();
                    var value = Value(depth + 1);
                    if (!seen.Add(key))
                    {
                        throw new CanonicalPayloadException(CanonicalPayloadError.DuplicateKey, "duplicate object key \"" + key + "\"");
                    }
                    obj.Entries.Add(new KeyValuePair<string, Node>(key, value));
                    SkipWs();
                    if (Eat(","))
                    {
                        continue;
                    }
                    if (Eat("}"))
                    {
                        return obj;
                    }
                    throw Malformed("expected `,` or `}`");
                }
            }

            private Node Array(int depth)
            {
                _pos++;
                var arr = new Arr();
                SkipWs();
                if (Eat("]"))
                {
                    return arr;
                }
                while (true)
                {
                    SkipWs();
                    arr.Items.Add(Value(depth + 1));
                    SkipWs();
                    if (Eat(","))
                    {
                        continue;
                    }
                    if (Eat("]"))
                    {
                        return arr;
                    }
                    throw Malformed("expected `,` or `]`");
                }
            }

            private int Hex4()
            {
                if (_pos + 4 > _text.Length)
                {
                    throw Malformed("bad \\u escape");
                }
                var v = 0;
                for (var i = 0; i < 4; i++)
                {
                    var c = _text[_pos + i];
                    int d;
                    if (c >= '0' && c <= '9')
                    {
                        d = c - '0';
                    }
                    else if (c >= 'a' && c <= 'f')
                    {
                        d = c - 'a' + 10;
                    }
                    else if (c >= 'A' && c <= 'F')
                    {
                        d = c - 'A' + 10;
                    }
                    else
                    {
                        throw Malformed("bad \\u escape");
                    }
                    v = (v << 4) | d;
                }
                _pos += 4;
                return v;
            }

            private string String()
            {
                _pos++;
                var sb = new StringBuilder();
                while (true)
                {
                    if (AtEnd)
                    {
                        throw Malformed("unterminated string");
                    }
                    var c = _text[_pos++];
                    if (c == '"')
                    {
                        return sb.ToString();
                    }
                    if (c == '\\')
                    {
                        var esc = AtEnd ? '\0' : _text[_pos];
                        var hadEsc = !AtEnd;
                        _pos++;
                        if (!hadEsc)
                        {
                            throw Malformed("bad escape");
                        }
                        switch (esc)
                        {
                            case '"': sb.Append('"'); break;
                            case '\\': sb.Append('\\'); break;
                            case '/': sb.Append('/'); break;
                            case 'b': sb.Append('\b'); break;
                            case 'f': sb.Append('\f'); break;
                            case 'n': sb.Append('\n'); break;
                            case 'r': sb.Append('\r'); break;
                            case 't': sb.Append('\t'); break;
                            case 'u':
                                var hi = Hex4();
                                if (hi == 0)
                                {
                                    throw new CanonicalPayloadException(CanonicalPayloadError.NulCharacter, "string or object key contains U+0000");
                                }
                                if (hi >= 0xD800 && hi < 0xDC00)
                                {
                                    if (!Eat("\\u"))
                                    {
                                        throw Malformed("lone surrogate");
                                    }
                                    var lo = Hex4();
                                    if (lo < 0xDC00 || lo >= 0xE000)
                                    {
                                        throw Malformed("lone surrogate");
                                    }
                                    sb.Append((char)hi).Append((char)lo);
                                }
                                else if (hi >= 0xDC00 && hi < 0xE000)
                                {
                                    throw Malformed("lone surrogate");
                                }
                                else
                                {
                                    sb.Append((char)hi);
                                }
                                break;
                            default:
                                throw Malformed("bad escape");
                        }
                    }
                    else if (c < 0x20)
                    {
                        throw Malformed("raw control character");
                    }
                    else if (char.IsHighSurrogate(c))
                    {
                        if (AtEnd || !char.IsLowSurrogate(_text[_pos]))
                        {
                            throw Malformed("lone surrogate");
                        }
                        sb.Append(c).Append(_text[_pos++]);
                    }
                    else if (char.IsLowSurrogate(c))
                    {
                        throw Malformed("lone surrogate");
                    }
                    else
                    {
                        sb.Append(c);
                    }
                }
            }

            private int Digits()
            {
                var from = _pos;
                while (_pos < _text.Length && _text[_pos] >= '0' && _text[_pos] <= '9')
                {
                    _pos++;
                }
                return _pos - from;
            }

            private Node Number()
            {
                var start = _pos;
                Eat("-");
                if (Peek() == '0')
                {
                    _pos++;
                }
                else if (Digits() == 0)
                {
                    throw Malformed("bad number");
                }
                var integerForm = true;
                if (Eat("."))
                {
                    integerForm = false;
                    if (Digits() == 0)
                    {
                        throw Malformed("bad number");
                    }
                }
                if (!AtEnd && (_text[_pos] == 'e' || _text[_pos] == 'E'))
                {
                    integerForm = false;
                    _pos++;
                    if (!AtEnd && (_text[_pos] == '+' || _text[_pos] == '-'))
                    {
                        _pos++;
                    }
                    if (Digits() == 0)
                    {
                        throw Malformed("bad number");
                    }
                }
                var token = _text.Substring(start, _pos - start);
                if (!(integerForm ? NumberText.IsValidInteger(token) : NumberText.IsValidDecimal(token)))
                {
                    throw new CanonicalPayloadException(
                        CanonicalPayloadError.InvalidNumber,
                        "number `" + token + "` is not exactly representable as an IEEE double; use a string");
                }
                return new Literal(token);
            }
        }

        /// <summary>Judges a number token from its text alone: valid exactly when the token is already what
        /// ECMAScript would print for the double it denotes.</summary>
        private static class NumberText
        {
            public static bool IsValidInteger(string token)
            {
                if (token == "-0")
                {
                    return false;
                }
                var digits = token[0] == '-' ? token.Substring(1) : token;
                return digits.Length <= 16 && long.Parse(digits, NumberStyles.None, CultureInfo.InvariantCulture) <= MaxSafeInteger;
            }

            public static bool IsValidDecimal(string token)
            {
                var negative = token[0] == '-';
                var body = negative ? token.Substring(1) : token;
                var ePos = body.IndexOfAny(new[] { 'e', 'E' });
                var mantissa = ePos < 0 ? body : body.Substring(0, ePos);
                var exponent = ePos < 0 ? BigInteger.Zero : BigInteger.Parse(body.Substring(ePos + 1), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
                var dot = mantissa.IndexOf('.');
                var intPart = dot < 0 ? mantissa : mantissa.Substring(0, dot);
                var all = intPart + (dot < 0 ? string.Empty : mantissa.Substring(dot + 1));

                // value = 0.DIGITS x 10^n once leading zeros are stripped.
                var lead = 0;
                while (lead < all.Length && all[lead] == '0')
                {
                    lead++;
                }
                var digits = all.Substring(lead).TrimEnd('0');
                if (digits.Length == 0)
                {
                    return false;
                }
                var nBig = exponent + intPart.Length - lead;
                if (nBig > 400 || nBig < -400)
                {
                    return false;
                }
                var n = (int)nBig;
                var k = digits.Length;
                if (k <= n || k > MaxSignificantDigits)
                {
                    return false;
                }
                if (!IsRepresentable(digits, n))
                {
                    return false;
                }
                return string.Equals(Es6((negative ? "-" : string.Empty), digits, n), token, StringComparison.Ordinal);
            }

            // A valid number is non-integral with at most 15 digits, so it never overflows; across the normal range
            // 15 digits always round-trip, so the text decides and only subnormals need the double itself.
            private static bool IsRepresentable(string digits, int n)
            {
                var e10 = n - 1;
                if (e10 >= -307)
                {
                    return true;
                }
                if (!double.TryParse(
                        digits + "E" + (n - digits.Length).ToString(CultureInfo.InvariantCulture),
                        NumberStyles.Float,
                        CultureInfo.InvariantCulture,
                        out var d) || d == 0 || double.IsInfinity(d))
                {
                    return false;
                }
                return ShortestDigits(d) == digits;
            }

            // Shortest round-trip digits of a positive double, from .NET's own shortest "R" formatting.
            private static string ShortestDigits(double d)
            {
                var r = d.ToString("R", CultureInfo.InvariantCulture);
                var e = r.IndexOf('E');
                var mantissa = e < 0 ? r : r.Substring(0, e);
                return mantissa.Replace(".", string.Empty).TrimStart('0').TrimEnd('0');
            }

            // ECMAScript Number::toString for digits d1..dk and decimal point position n.
            private static string Es6(string sign, string digits, int n)
            {
                var k = digits.Length;
                var sb = new StringBuilder(sign);
                if (k <= n && n <= 21)
                {
                    sb.Append(digits).Append('0', n - k);
                }
                else if (0 < n && n <= 21)
                {
                    sb.Append(digits, 0, n).Append('.').Append(digits, n, k - n);
                }
                else if (-6 < n && n <= 0)
                {
                    sb.Append("0.").Append('0', -n).Append(digits);
                }
                else
                {
                    var e = n - 1;
                    sb.Append(digits[0]);
                    if (k > 1)
                    {
                        sb.Append('.').Append(digits, 1, k - 1);
                    }
                    sb.Append('e').Append(e < 0 ? '-' : '+').Append(Math.Abs(e).ToString(CultureInfo.InvariantCulture));
                }
                return sb.ToString();
            }
        }
    }
}
