using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace Avalon.Sdk.Tests;

public class UnknownIdSchemeTests
{
    private const string Id = "7c26a0e34260b2c5bb6a795e29cdfe878c907df4bf8c7425c5a8ce00235558e9";

    [Fact]
    public void ParseReportsAnotherLengthAsAnUnknownScheme()
    {
        Assert.Equal(63, Assert.Throws<UnknownIdSchemeException>(() => IdentityId.Parse(Id.Substring(1))).Length);
        Assert.Equal(65, Assert.Throws<UnknownIdSchemeException>(() => IdentityId.Parse(Id + "\n")).Length);
        Assert.Equal(0, Assert.Throws<UnknownIdSchemeException>(() => IdentityId.Parse("")).Length);
        Assert.False(IdentityId.TryParse(Id + "\n", out _));
    }

    [Fact]
    public void LengthIsCountedInUtf8Bytes()
    {
        // 32 two-byte characters are 64 bytes (malformed, not another scheme); 33 are 66 bytes.
        var malformed = Assert.ThrowsAny<FormatException>(() => IdentityId.Parse(new string('é', 32)));
        Assert.IsNotType<UnknownIdSchemeException>(malformed);
        Assert.Equal(66, Assert.Throws<UnknownIdSchemeException>(() => IdentityId.Parse(new string('é', 33))).Length);
    }

    [Fact]
    public void SixtyFourNonHexCharactersStayTheGenericCase()
    {
        var ex = Assert.ThrowsAny<FormatException>(() => IdentityId.Parse(Id.ToUpperInvariant()));
        Assert.IsNotType<UnknownIdSchemeException>(ex);
    }

    [Fact]
    public async Task ServerCodeMapsToATypedException()
    {
        var response = new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent(@"{""error"":""unknown identity id scheme: 63 characters; a newer version may be required"",""code"":""UNKNOWN_ID_SCHEME""}"),
        };
        var ex = Assert.IsType<AvalonUnknownIdSchemeException>(await Session.ServerErrorAsync(response));
        Assert.Equal(63, ex.Length);
        Assert.Equal("UNKNOWN_ID_SCHEME", ex.Code);
        Assert.Equal(HttpStatusCode.BadRequest, ex.StatusCode);
    }

    [Fact]
    public async Task InvalidIdentityIdStaysAPlainRequestException()
    {
        var response = new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent(@"{""error"":""bad"",""code"":""INVALID_IDENTITY_ID""}"),
        };
        Assert.IsType<AvalonRequestException>(await Session.ServerErrorAsync(response));
    }
}
