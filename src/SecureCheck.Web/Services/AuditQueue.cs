using System.Threading.Channels;

namespace SecureCheck.Web.Services;

/// <summary>
/// Thread-safe singleton background queue of AuditRun IDs backed by an unbounded System.Threading.Channels channel.
/// Multiple HTTP requests may enqueue runs concurrently while AuditWorker consumes them sequentially.
/// </summary>
public sealed class AuditQueue
{
    private readonly Channel<int> _channel = Channel.CreateUnbounded<int>(new UnboundedChannelOptions
    {
        SingleReader = true,
        SingleWriter = false
    });

    /// <summary>
    /// Enqueues an AuditRun primary key for background execution.
    /// </summary>
    public ValueTask EnqueueAsync(int auditRunId, CancellationToken ct = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(auditRunId);
        return _channel.Writer.WriteAsync(auditRunId, ct);
    }

    /// <summary>
    /// Waits for and dequeues the next AuditRun primary key.
    /// </summary>
    public ValueTask<int> DequeueAsync(CancellationToken ct = default) =>
        _channel.Reader.ReadAsync(ct);

    /// <summary>
    /// Streams queued AuditRun primary keys until cancellation is requested.
    /// </summary>
    public IAsyncEnumerable<int> ReadAllAsync(CancellationToken ct = default) =>
        _channel.Reader.ReadAllAsync(ct);
}

