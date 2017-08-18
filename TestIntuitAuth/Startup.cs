using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Newtonsoft.Json.Linq;
using System.Security.Claims;
using System.Net;
using System.IO;

namespace TestIntuitAuth
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            Environment = env;

            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);

            if (env.IsDevelopment())
            {
                // For more details on using the user secret store see http://go.microsoft.com/fwlink/?LinkID=532709
                builder.AddUserSecrets<Startup>();
            }

            builder.AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfiguration Configuration { get; set; }

        public IHostingEnvironment Environment { get; set; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(sharedOptions =>
            {
                sharedOptions.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                sharedOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                sharedOptions.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
                .AddCookie()
                .AddOpenIdConnect(o =>
                {
                    o.UseTokenLifetime = true;
                    o.ClientId = Configuration["intuit:oidc:clientid"];
                    o.ClientSecret = Configuration["intuit:oidc:clientsecret"];
                    o.ResponseType = OpenIdConnectResponseType.Code;
                    o.MetadataAddress = "https://developer.api.intuit.com/.well-known/openid_sandbox_configuration/";
                    o.ProtocolValidator.RequireNonce = false;
                    o.SaveTokens = true;
                    o.GetClaimsFromUserInfoEndpoint = true;
                    o.ClaimActions.MapUniqueJsonKey("given_name", "givenName");
                    o.ClaimActions.MapUniqueJsonKey("family_name", "familyName");
                    o.ClaimActions.MapUniqueJsonKey(ClaimTypes.Email, "email"); //should work but because the middleware checks for claims w/ the same value and the claim for "email" already exists it doesn't get mapped.
                    o.Scope.Add("phone");
                    o.Scope.Add("email");
                    o.Scope.Add("address");
                    o.Scope.Add("com.intuit.quickbooks.accounting");
                    o.Events = new OpenIdConnectEvents()
                    {
                        OnAuthenticationFailed = c =>
                        {
                            c.HandleResponse();

                            c.Response.StatusCode = 500;
                            c.Response.ContentType = "text/plain";
                            return c.Response.WriteAsync(c.Exception.ToString());
                        },
                        OnUserInformationReceived = context =>
                        {
                            var identity = (ClaimsIdentity)context.Principal.Identity;
                            string fullName = GetFullName(context);
                            if (fullName.Length > 0)
                            {
                                identity.AddClaim(new Claim("name", fullName, "Intuit"));
                            }
                            string email = GetUserValue(context, "email");
                            if (email.Length > 0)
                            {
                                identity.AddClaim(new Claim(ClaimTypes.Email, email, null, "Intuit"));
                            }
                            return Task.CompletedTask;
                        }

                    };
                });
        }

        private static string GetUserValue(UserInformationReceivedContext context, string valName)
        {
            string val = "";

            JToken valToken;
            if (context.User.TryGetValue(valName, out valToken))
            {
                val = valToken.Value<string>();
            }
            return val;
        }

        private static string GetFullName(UserInformationReceivedContext context)
        {
            string fullName = "";

            JToken givenName, familyName;
            if (context.User.TryGetValue("givenName", out givenName))
            {
                fullName = givenName.Value<string>() + " ";
            }
            if (context.User.TryGetValue("familyName", out familyName))
            {
                fullName += familyName.Value<string>();
            }

            return fullName;
        }

        public void Configure(IApplicationBuilder app, IOptionsMonitor<OpenIdConnectOptions> optionsMonitor)
        {
            app.UseDeveloperExceptionPage();
            app.UseAuthentication();

            app.Run(async context =>
            {
                var response = context.Response;

                if (context.Request.Path.Equals("/signedout"))
                {
                    await WriteHtmlAsync(response, async res =>
                    {
                        await res.WriteAsync($"<h1>You have been signed out.</h1>");
                        await res.WriteAsync("<a class=\"btn btn-default\" href=\"/\">Home</a>");
                    });
                    return;
                }

                if (context.Request.Path.Equals("/signout"))
                {
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    await WriteHtmlAsync(response, async res =>
                    {
                        await res.WriteAsync($"<h1>Signed out {HtmlEncode(context.User.Identity.Name)}</h1>");
                        await res.WriteAsync("<a class=\"btn btn-default\" href=\"/\">Home</a>");
                    });
                    return;
                }

                if (context.Request.Path.Equals("/signout-remote"))
                {
                    // Redirects
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties()
                    {
                        RedirectUri = "/signedout"
                    });
                    return;
                }

                if (context.Request.Path.Equals("/Account/AccessDenied"))
                {
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    await WriteHtmlAsync(response, async res =>
                    {
                        await res.WriteAsync($"<h1>Access Denied for user {HtmlEncode(context.User.Identity.Name)} to resource '{HtmlEncode(context.Request.Query["ReturnUrl"])}'</h1>");
                        await res.WriteAsync("<a class=\"btn btn-default\" href=\"/signout\">Sign Out</a>");
                        await res.WriteAsync("<a class=\"btn btn-default\" href=\"/\">Home</a>");
                    });
                    return;
                }

                // DefaultAuthenticateScheme causes User to be set
                // var user = context.User;

                // This is what [Authorize] calls
                var userResult = await context.AuthenticateAsync();
                var user = userResult.Principal;
                var props = userResult.Properties;

                // This is what [Authorize(ActiveAuthenticationSchemes = OpenIdConnectDefaults.AuthenticationScheme)] calls
                // var user = await context.AuthenticateAsync(OpenIdConnectDefaults.AuthenticationScheme);

                // Not authenticated
                if (user == null || !user.Identities.Any(identity => identity.IsAuthenticated))
                {
                    // This is what [Authorize] calls
                    await context.ChallengeAsync();

                    // This is what [Authorize(ActiveAuthenticationSchemes = OpenIdConnectDefaults.AuthenticationScheme)] calls
                    // await context.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme);

                    return;
                }

                // Authenticated, but not authorized
                if (context.Request.Path.Equals("/restricted") && !user.Identities.Any(identity => identity.HasClaim("special", "true")))
                {
                    await context.ForbidAsync();
                    return;
                }

                if (context.Request.Path.Equals("/create-invoice"))
                {
                    var access_token = props.GetTokenValue("access_token");
                    HttpWebRequest qboApiRequest = (HttpWebRequest)WebRequest.Create(Configuration["QuickBooksAPIEndpoint"] + "/invoice");
                    qboApiRequest.Method = "POST";
                    qboApiRequest.Headers["Authorization"] = string.Format("Bearer {0}", access_token);
                    qboApiRequest.ContentType = "application/json;charset=UTF-8";
                    qboApiRequest.Accept = "application/json";
                    var stream = await qboApiRequest.GetRequestStreamAsync();
                    var jsonString = "{\"Line\": [{\"Amount\": 100.00,\"DetailType\": \"SalesItemLineDetail\",\"SalesItemLineDetail\": {\"ItemRef\": {\"value\": \"1\",\"name\": \"Services\"}}}],\"CustomerRef\": {\"value\": \"1\"}}";

                    using (var streamWriter = new StreamWriter(stream))
                    {
                        streamWriter.Write(jsonString);
                        streamWriter.Flush();
                    }

                    try
                    {
                        // get the response
                        var apiResponse = await qboApiRequest.GetResponseAsync();
                        HttpWebResponse qboApiResponse = (HttpWebResponse)apiResponse;
                        //read qbo api response
                        using (var qboApiReader = new StreamReader(qboApiResponse.GetResponseStream()))
                        {
                            var result = qboApiReader.ReadToEnd();
                            await WriteHtmlAsync(response, async res =>
                            {
                                await res.WriteAsync("Response<br>");
                                await res.WriteAsync($"{result}");
                            });
                            return;
                        }
                    }
                    catch (WebException ex)
                    {
                        //if (ex.Message.Contains("401"))
                        //{
                        //    //need to get new token from refresh token
                        //    System.Diagnostics.Debug.WriteLine(ex.Message);
                        //}
                        //else
                        //{
                        //    System.Diagnostics.Debug.WriteLine(ex.Message);
                        //    //return "";
                        //}
                        //return ex.Message;
                    }
                }

                if (context.Request.Path.Equals("/refresh"))
                {
                    var refreshToken = props.GetTokenValue("refresh_token");

                    if (string.IsNullOrEmpty(refreshToken))
                    {
                        await WriteHtmlAsync(response, async res =>
                        {
                            await res.WriteAsync($"No refresh_token is available.<br>");
                            await res.WriteAsync("<a class=\"btn btn-link\" href=\"/signout\">Sign Out</a>");
                        });

                        return;
                    }

                    var options = optionsMonitor.Get(OpenIdConnectDefaults.AuthenticationScheme);
                    var metadata = await options.ConfigurationManager.GetConfigurationAsync(context.RequestAborted);

                    var pairs = new Dictionary<string, string>()
                    {
                        { "client_id", options.ClientId },
                        { "client_secret", options.ClientSecret },
                        { "grant_type", "refresh_token" },
                        { "refresh_token", refreshToken }
                    };
                    var content = new FormUrlEncodedContent(pairs);
                    var tokenResponse = await options.Backchannel.PostAsync(metadata.TokenEndpoint, content, context.RequestAborted);
                    tokenResponse.EnsureSuccessStatusCode();

                    var payload = JObject.Parse(await tokenResponse.Content.ReadAsStringAsync());

                    // Persist the new acess token
                    props.UpdateTokenValue("access_token", payload.Value<string>("access_token"));
                    props.UpdateTokenValue("refresh_token", payload.Value<string>("refresh_token"));
                    if (int.TryParse(payload.Value<string>("expires_in"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds))
                    {
                        var expiresAt = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(seconds);
                        props.UpdateTokenValue("expires_at", expiresAt.ToString("o", CultureInfo.InvariantCulture));
                    }
                    await context.SignInAsync(user, props);

                    await WriteHtmlAsync(response, async res =>
                    {
                        await res.WriteAsync($"<h1>Refreshed.</h1>");
                        await res.WriteAsync("<a class=\"btn btn-default\" href=\"/refresh\">Refresh tokens</a>");
                        await res.WriteAsync("<a class=\"btn btn-default\" href=\"/\">Home</a>");

                        await res.WriteAsync("<h2>Tokens:</h2>");
                        await WriteTableHeader(res, new string[] { "Token Type", "Value" }, props.GetTokens().Select(token => new string[] { token.Name, token.Value }));

                        await res.WriteAsync("<h2>Payload:</h2>");
                        await res.WriteAsync(HtmlEncoder.Default.Encode(payload.ToString()).Replace(",", ",<br>") + "<br>");
                    });

                    return;
                }

                await WriteHtmlAsync(response, async res =>
                {
                    await res.WriteAsync($"<h1>Hello Authenticated User {HtmlEncode(user.Identity.Name)}</h1>");
                    await res.WriteAsync("<a class=\"btn btn-default\" href=\"/refresh\">Refresh tokens</a>");
                    await res.WriteAsync("<a class=\"btn btn-default\" href=\"/restricted\">Restricted</a>");
                    await res.WriteAsync("<a class=\"btn btn-default\" href=\"/signout\">Sign Out</a>");
                    await res.WriteAsync("<a class=\"btn btn-default\" href=\"/signout-remote\">Sign Out Remote</a>");

                    await res.WriteAsync("<h2>Claims:</h2>");
                    await WriteTableHeader(res, new string[] { "Claim Type", "Value" }, context.User.Claims.Select(c => new string[] { c.Type, c.Value }));

                    await res.WriteAsync("<h2>Tokens:</h2>");
                    await WriteTableHeader(res, new string[] { "Token Type", "Value" }, props.GetTokens().Select(token => new string[] { token.Name, token.Value }));

                    await res.WriteAsync($"<h2>Current Time UTC:{DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture)}</h2>");

                });
            });
        }

        private static async Task WriteHtmlAsync(HttpResponse response, Func<HttpResponse, Task> writeContent)
        {
            var bootstrap = "<link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css\" integrity=\"sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u\" crossorigin=\"anonymous\">";

            response.ContentType = "text/html";
            await response.WriteAsync($"<html><head>{bootstrap}</head><body><div class=\"container\">");
            await writeContent(response);
            await response.WriteAsync("</div></body></html>");
        }

        private static async Task WriteTableHeader(HttpResponse response, IEnumerable<string> columns, IEnumerable<IEnumerable<string>> data)
        {
            await response.WriteAsync("<table class=\"table table-condensed\">");
            await response.WriteAsync("<tr>");
            foreach (var column in columns)
            {
                await response.WriteAsync($"<th>{HtmlEncode(column)}</th>");
            }
            await response.WriteAsync("</tr>");
            foreach (var row in data)
            {
                await response.WriteAsync("<tr>");
                foreach (var column in row)
                {
                    await response.WriteAsync($"<td>{HtmlEncode(column)}</td>");
                }
                await response.WriteAsync("</tr>");
            }
            await response.WriteAsync("</table>");
        }

        private static string HtmlEncode(string content) =>
            string.IsNullOrEmpty(content) ? string.Empty : HtmlEncoder.Default.Encode(content);
    }
}
