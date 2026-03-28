using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sentinel.Core.Interfaces;
using Sentinel.Core.Models;
using Sentinel.Network.Logging;
using Sentinel.Network.Proxy;

var builder = Host.CreateApplicationBuilder(args);

// Ensure appsettings.json is found next to the executable,
// not in whatever directory `dotnet run` was invoked from.
builder.Configuration.SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false);

// Bind proxy configuration from appsettings.json
builder.Services.Configure<ProxyConfiguration>(
    builder.Configuration.GetSection(ProxyConfiguration.SectionName));

// Register services
builder.Services.AddSingleton<IPacketLogger, PacketLogger>();
builder.Services.AddSingleton<ProxyHost>();

// Configure console logging format
builder.Logging.AddSimpleConsole(options =>
{
    options.SingleLine = true;
    options.TimestampFormat = "HH:mm:ss ";
});

var host = builder.Build();

// Print banner
Console.WriteLine();
Console.WriteLine("  ╔═══════════════════════════════════════╗");
Console.WriteLine("  ║         Sentinel Proxy v0.1.0         ║");
Console.WriteLine("  ║   Conquer Online Traffic Interceptor  ║");
Console.WriteLine("  ╚═══════════════════════════════════════╝");
Console.WriteLine();

// Run the proxy
var proxyHost = host.Services.GetRequiredService<ProxyHost>();
var logger = host.Services.GetRequiredService<ILogger<Program>>();

using var cts = new CancellationTokenSource();

Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    logger.LogInformation("Shutdown requested (Ctrl+C)...");
    cts.Cancel();
};

try
{
    await proxyHost.RunAsync(cts.Token);
}
catch (OperationCanceledException)
{
    // Normal shutdown
}
finally
{
    await proxyHost.DisposeAsync();
    logger.LogInformation("Sentinel proxy shut down");
}
