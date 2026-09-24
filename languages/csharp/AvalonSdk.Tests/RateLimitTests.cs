using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace Avalon.Sdk.Tests;

public class RateLimitTests
{
    private static HttpResponseMessage Response(int status, string? retryAfter)
    {
        var response = new HttpResponseMessage((HttpStatusCode)status)
        {
            Content = new StringContent(@"{""error"":""slow down"",""code"":""RATE_LIMITED""}"),
        };
        if (retryAfter != null)
        {
            response.Headers.TryAddWithoutValidation("Retry-After", retryAfter);
        }
        return response;
    }

    [Fact]
    public async Task Maps429WithNumericRetryAfter()
    {
        var ex = Assert.IsType<AvalonRequestException>(await Session.ServerErrorAsync(Response(429, "7")));
        Assert.True(ex.IsRateLimited);
        Assert.Equal((HttpStatusCode)429, ex.StatusCode);
        Assert.Equal("RATE_LIMITED", ex.Code);
        Assert.Equal(TimeSpan.FromSeconds(7), ex.RetryAfter);
    }

    [Fact]
    public async Task Maps429WithoutRetryAfter()
    {
        var ex = Assert.IsType<AvalonRequestException>(await Session.ServerErrorAsync(Response(429, null)));
        Assert.True(ex.IsRateLimited);
        Assert.Null(ex.RetryAfter);
    }

    [Theory]
    [InlineData("soon")]
    [InlineData("Wed, 21 Oct 2026 07:28:00 GMT")]
    [InlineData("-3")]
    [InlineData("1.5")]
    [InlineData("")]
    [InlineData("99999999999999999999")]
    public async Task IgnoresNonNumericRetryAfter(string value)
    {
        var ex = Assert.IsType<AvalonRequestException>(await Session.ServerErrorAsync(Response(429, value)));
        Assert.True(ex.IsRateLimited);
        Assert.Null(ex.RetryAfter);
    }

    [Fact]
    public async Task OtherStatusesAreNotRateLimited()
    {
        var ex = Assert.IsType<AvalonRequestException>(await Session.ServerErrorAsync(Response(503, "5")));
        Assert.False(ex.IsRateLimited);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, ex.StatusCode);

        var plain = new AvalonRequestException(HttpStatusCode.NotFound);
        Assert.Null(plain.RetryAfter);
        Assert.False(plain.IsRateLimited);
    }
}
