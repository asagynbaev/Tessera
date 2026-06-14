using System.Security.Cryptography;
using Tessera.Channels;

namespace Tessera.Channels.Tests;

public class PepperProviderTests
{
    [Fact]
    public async Task StaticPepper_RoundTrips()
    {
        var pepper = RandomNumberGenerator.GetBytes(32);
        var provider = new StaticPepperProvider(pepper);

        var read = await provider.GetPepperAsync();
        Assert.Equal(pepper, read.ToArray());
    }

    [Fact]
    public void StaticPepper_ShortPepper_Throws()
    {
        Assert.Throws<ArgumentException>(() => new StaticPepperProvider(new byte[16]));
        Assert.Throws<ArgumentException>(() => new StaticPepperProvider(new byte[31]));
    }

    [Fact]
    public void StaticPepper_AllZero_Throws()
    {
        // M5: an all-zero buffer of the correct length must be rejected — it offers no security.
        Assert.Throws<ArgumentException>(() => new StaticPepperProvider(new byte[32]));
        Assert.Throws<ArgumentException>(() => new StaticPepperProvider(new byte[64]));
    }

    [Fact]
    public void StaticPepper_LowEntropy_Throws()
    {
        // A repeated single byte across 32 bytes is grossly low entropy and must be rejected.
        var lowEntropy = new byte[32];
        Array.Fill(lowEntropy, (byte)0x42);
        Assert.Throws<ArgumentException>(() => new StaticPepperProvider(lowEntropy));
    }

    [Fact]
    public void EnvironmentPepper_AllZero_Throws()
    {
        var name = "ZKP_TEST_PEPPER_" + Guid.NewGuid().ToString("N");
        try
        {
            Environment.SetEnvironmentVariable(name, Convert.ToBase64String(new byte[32]));
            var provider = new EnvironmentPepperProvider(name);
            Assert.Throws<InvalidOperationException>(() =>
                provider.GetPepperAsync().AsTask().GetAwaiter().GetResult());
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }

    [Fact]
    public void EnvironmentPepper_MissingVariable_Throws()
    {
        var name = "ZKP_TEST_PEPPER_" + Guid.NewGuid().ToString("N");
        var provider = new EnvironmentPepperProvider(name);
        Assert.Throws<InvalidOperationException>(() => provider.GetPepperAsync().AsTask().GetAwaiter().GetResult());
    }

    [Fact]
    public void EnvironmentPepper_InvalidBase64_Throws()
    {
        var name = "ZKP_TEST_PEPPER_" + Guid.NewGuid().ToString("N");
        try
        {
            Environment.SetEnvironmentVariable(name, "not!valid!base64!");
            var provider = new EnvironmentPepperProvider(name);
            Assert.Throws<InvalidOperationException>(() =>
                provider.GetPepperAsync().AsTask().GetAwaiter().GetResult());
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }

    [Fact]
    public async Task EnvironmentPepper_ValidBase64_Decodes()
    {
        var name = "ZKP_TEST_PEPPER_" + Guid.NewGuid().ToString("N");
        var raw = RandomNumberGenerator.GetBytes(32);
        try
        {
            Environment.SetEnvironmentVariable(name, Convert.ToBase64String(raw));
            var provider = new EnvironmentPepperProvider(name);
            var read = await provider.GetPepperAsync();
            Assert.Equal(raw, read.ToArray());
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }

    [Fact]
    public void EnvironmentPepper_ShortPepper_Throws()
    {
        var name = "ZKP_TEST_PEPPER_" + Guid.NewGuid().ToString("N");
        try
        {
            Environment.SetEnvironmentVariable(name, Convert.ToBase64String(new byte[16]));
            var provider = new EnvironmentPepperProvider(name);
            Assert.Throws<InvalidOperationException>(() =>
                provider.GetPepperAsync().AsTask().GetAwaiter().GetResult());
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }
}
