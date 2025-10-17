
namespace FortressAuth.Api.Middleware;

public class SecurityHeadersMiddleware(RequestDelegate next, IWebHostEnvironment env)
{
    public async Task Invoke(HttpContext ctx)
    {
        var h = ctx.Response.Headers;
        h["X-Content-Type-Options"] = "nosniff";
        h["X-Frame-Options"] = "DENY";
        h["Referrer-Policy"] = "no-referrer";
        h["X-XSS-Protection"] = "0";
        if (!env.IsDevelopment())
        {
            h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload";
            h["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";
        }
        await next(ctx);
    }
}
