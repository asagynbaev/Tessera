namespace Tessera.Sources.Bitcoin.Tests;

/// <summary>A controllable <see cref="TimeProvider"/> for deterministic time in tests.</summary>
internal sealed class FakeClock : TimeProvider
{
    private DateTimeOffset _now;

    public FakeClock(DateTimeOffset now) => _now = now;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;

    public void Set(DateTimeOffset now) => _now = now;
}
