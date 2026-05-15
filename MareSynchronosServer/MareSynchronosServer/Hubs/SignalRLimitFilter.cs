using AspNetCoreRateLimit;
using MareSynchronosShared;
using MareSynchronosShared.Utils;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Options;

namespace MareSynchronosServer.Hubs;
public class SignalRLimitFilter : IHubFilter
{
    private readonly IRateLimitProcessor _processor;
    private readonly IHttpContextAccessor _accessor;
    private readonly ILogger<SignalRLimitFilter> _logger;
    private static readonly SemaphoreSlim _connectionLimiterSemaphore = new(20, 20);
    private static readonly SemaphoreSlim _disconnectLimiterSemaphore = new(20, 20);

    public SignalRLimitFilter(
        IOptions<IpRateLimitOptions> options, IProcessingStrategy processing, IIpPolicyStore policyStore, IHttpContextAccessor accessor, ILogger<SignalRLimitFilter> logger)
    {
        _processor = new IpRateLimitProcessor(options?.Value, policyStore, processing);
        this._accessor = accessor;
        this._logger = logger;
    }

    public async ValueTask<object> InvokeMethodAsync(
        HubInvocationContext invocationContext, Func<HubInvocationContext, ValueTask<object>> next)
    {
        var ip = _accessor.GetIpAddress();
        var client = new ClientRequestIdentity
        {
            ClientIp = ip,
            Path = invocationContext.HubMethodName,
            HttpVerb = "ws",
            ClientId = invocationContext.Context.UserIdentifier,
        };
        foreach (var rule in await _processor.GetMatchingRulesAsync(client).ConfigureAwait(false))
        {
            var counter = await _processor.ProcessRequestAsync(client, rule).ConfigureAwait(false);
            if (counter.Count > rule.Limit)
            {
                var authUserId = invocationContext.Context.User.Claims?.SingleOrDefault(c => string.Equals(c.Type, MareClaimTypes.Uid, StringComparison.Ordinal))?.Value ?? "Unknown";
                var retry = counter.Timestamp.RetryAfterFrom(rule);
                _logger.LogWarning("Method rate limit triggered from {ip}/{authUserId}: {method}", ip, authUserId, invocationContext.HubMethodName);
                throw new HubException($"call limit {retry}");
            }
        }

        return await next(invocationContext).ConfigureAwait(false);
    }

    // Optional method
    /* public async Task OnConnectedAsync(HubLifetimeContext context, Func<HubLifetimeContext, Task> next)
    {
        await _connectionLimiterSemaphore.WaitAsync().ConfigureAwait(false);
        try
        {
            var ip = _accessor.GetIpAddress();
            var client = new ClientRequestIdentity
            {
                ClientIp = ip,
                Path = "Connect",
                HttpVerb = "ws",
            };
            foreach (var rule in await _processor.GetMatchingRulesAsync(client).ConfigureAwait(false))
            {
                var counter = await _processor.ProcessRequestAsync(client, rule).ConfigureAwait(false);
                if (counter.Count > rule.Limit)
                {
                    var retry = counter.Timestamp.RetryAfterFrom(rule);
                    _logger.LogWarning("Connection rate limit triggered from {ip}", ip);
                    _connectionLimiterSemaphore.Release();
                    throw new HubException($"Connection rate limit {retry}");
                }
            }


            await Task.Delay(25).ConfigureAwait(false);
            await next(context).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error on OnConnectedAsync");
        }
        finally
        {
            _connectionLimiterSemaphore.Release();
        }
    }

    public async Task OnDisconnectedAsync(
        HubLifetimeContext context, Exception exception, Func<HubLifetimeContext, Exception, Task> next)
    {
        await _disconnectLimiterSemaphore.WaitAsync().ConfigureAwait(false);
        if (exception != null)
        {
            _logger.LogWarning(exception, "InitialException on OnDisconnectedAsync");
        }

        try
        {
            await next(context, exception).ConfigureAwait(false);
            await Task.Delay(25).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            _logger.LogWarning(e, "ThrownException on OnDisconnectedAsync");
        }
        finally
        {
            _disconnectLimiterSemaphore.Release();
        }
    } */
}
