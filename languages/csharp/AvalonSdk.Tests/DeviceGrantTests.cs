using System;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit;

namespace Avalon.Sdk.Tests;

public class DeviceGrantTests
{
    private static AccountSession SessionWithKey(StubHttpMessageHandler handler) =>
        AccountSession.ForTesting(
            handler.ToHttpClient(),
            signing: new AccountSession.SigningKeyMaterial(new Ed25519PrivateKeyParameters(new SecureRandom()), Guid.NewGuid()));

    private static string Base64(int length, int at = -1, byte value = 0)
    {
        var bytes = new byte[length];
        if (at >= 0)
        {
            bytes[at] = value;
        }
        return Convert.ToBase64String(bytes);
    }

    [Theory]
    [InlineData("AAAA")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=")] // non-canonical trailing bits
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= ")] // surrounding whitespace
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAA=")] // embedded whitespace
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")] // unpadded
    public async Task ApproveDeviceGrantAsync_RejectsAKeyThatIsNotCanonicalBase64Of32Bytes(string key)
    {
        var handler = new StubHttpMessageHandler();
        var session = SessionWithKey(handler);

        await Assert.ThrowsAsync<ArgumentException>(() => session.ApproveDeviceGrantAsync(Guid.NewGuid(), key));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task ApproveDeviceGrantAsync_RejectsASmallOrderKeyBeforeAnyRequest()
    {
        var handler = new StubHttpMessageHandler();
        var session = SessionWithKey(handler);

        // y = 1 is the identity point.
        await Assert.ThrowsAsync<ArgumentException>(
            () => session.ApproveDeviceGrantAsync(Guid.NewGuid(), Base64(32, 0, 1)));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task ApproveAndRevoke_FailLoudlyWithoutARequestUntilV3SigningLands()
    {
        var handler = new StubHttpMessageHandler();
        var session = SessionWithKey(handler);

        await Assert.ThrowsAsync<NotSupportedException>(() => session.RevokeDeviceAsync(Guid.NewGuid()));
        await Assert.ThrowsAsync<NotSupportedException>(
            () => session.ApproveDeviceGrantAsync(Guid.NewGuid(), Convert.ToBase64String(new Ed25519PrivateKeyParameters(new SecureRandom()).GeneratePublicKey().GetEncoded())));
        Assert.Empty(handler.Requests);
    }
}
