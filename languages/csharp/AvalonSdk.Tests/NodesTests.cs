using System.Threading.Tasks;
using Avalon.Sdk;
using Xunit;

namespace Avalon.Sdk.Tests;

public class NodesTests
{
    [Fact]
    public async Task GetNodeStatusAsync_ReturnsRoles()
    {
        var handler = new StubHttpMessageHandler()
            .Enqueue("""
            {
                "protocol_version": "0.1.0",
                "network_id": "avalon-dev-local",
                "roles": ["combined"],
                "stale": false,
                "newest_known_peer_version": "0.1.0"
            }
            """);
        var client = new AvalonClient(new AvalonConfig("https://example.invalid", "test-key"), handler.ToHttpClient());

        var status = await client.GetNodeStatusAsync();

        Assert.Equal(new[] { "combined" }, status.Roles);
        Assert.Equal("0.1.0", status.ProtocolVersion);
    }
}
