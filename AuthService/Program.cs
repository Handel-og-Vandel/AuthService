using NLog;
using NLog.Web;

var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();
logger.Debug("Starting authentication service");

try
{
    var builder = WebApplication.CreateBuilder(args);

    // NLog: Setup NLog for Dependency injection
    builder.Logging.ClearProviders();
    builder.Host.UseNLog();

    var environment = builder.Configuration["ASPNETCORE_ENVIRONMENT"] ?? "Development";

    // Add services to the container.
    if (environment == "Development")
    {
        logger.Debug("Using environment vault repository");
        builder.Services.AddSingleton<IKeyVaultRepository, EnvironmentVaultRepository>();
    }
    else
    {
        logger.Debug("Using HashiCorp vault repository");
        builder.Services.AddSingleton<IKeyVaultRepository, HashiCorpVaultRepository>();
    }
    builder.Services.AddHttpClient();
    builder.Services.AddControllers();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();

    var app = builder.Build();

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    //app.UseHttpsRedirection();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapControllers();

    app.MapGet("/", () => "Authentication service");

    app.Run();
}
catch (Exception ex)
{
    logger.Error(ex, "Stopped program because of exception");
    throw;
}
finally
{
    logger.Debug("Shutting down authentication service");
    NLog.LogManager.Shutdown();
}