using System.Security.Claims;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;
using CodeHollow.FeedReader;
using Dapper;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthorization();
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
}).AddCookie(options =>
{
    options.Events.OnRedirectToLogin = context =>
    {
        context.Response.StatusCode = 401;
        return Task.CompletedTask;
    };
    options.LoginPath = "/login";
});

var connectionString = builder.Configuration.GetConnectionString("FeedlyConnection");
var feedlyRepository = new FeedlyRepository(connectionString ?? string.Empty);
await feedlyRepository.CreateDatabaseTable();
builder.Services.AddSingleton(feedlyRepository);

builder.Services.AddAntiforgery();
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll",
        corsPolicyBuilder => corsPolicyBuilder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
});

builder.Services.AddLogging(logging =>
{
    logging.AddConsole();
    logging.AddDebug();
});

var app = builder.Build();
app.UseCors("AllowAll");
app.UseAntiforgery();
app.UseStaticFiles();
app.UseAuthorization();
app.MapFallbackToFile("feedpage.html");

app.MapGet("/", () => Results.File("feedpage.html", "text/html"));
app.MapGet("/antiforgery", (IAntiforgery antiforgery, HttpContext context) =>
{
    var token = antiforgery.GetAndStoreTokens(context);
    var html =
        $"""<input id="antiforgeryToken" name="{token.FormFieldName}" type="hidden" value="{token.RequestToken}" />""";
    return Results.Content(html, "text/html");
});

app.MapPost("/login",
    async ([FromForm] string email, [FromForm] string password, FeedlyRepository repo, HttpContext context) =>
    {
        var user = await repo.GetUser(email);
        if (user is null)
        {
            app.Logger.LogWarning("User not found");
            return Results.Unauthorized();
        }

        var hasher = new PasswordHasher<User>();
        var result = hasher.VerifyHashedPassword(user, user.Password, password);

        if (result != PasswordVerificationResult.Success)
        {
            app.Logger.LogWarning("Invalid password");
            return Results.Unauthorized();
        }

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Email),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()!)
        };
        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var authProperties = new AuthenticationProperties();
        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity), authProperties);
        return Results.Redirect("/feeds");
    });

app.MapPost("/register",
    async ([FromForm] string email, [FromForm] string password, FeedlyRepository repo, HttpContext context) =>
    {
        var user = await repo.GetUser(email);
        if (user is not null)
        {
            return Results.UnprocessableEntity("User already exists");
        }

        var hasher = new PasswordHasher<User>();
        var newUser = new User(null, email, password);
        newUser.Password = hasher.HashPassword(newUser, password);
        newUser.Id = await repo.AddUser(newUser);

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, newUser.Email),
            new(ClaimTypes.NameIdentifier, newUser.Id.ToString()!)
        };
        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var authProperties = new AuthenticationProperties();
        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity), authProperties);

        return Results.Redirect("/feeds");
    });

app.MapPost("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync();

    var html =
        """
        <div hx-get="/feeds" hx-target="#welcome" hx-swap="outerHTML" hx-trigger="load" id="welcome" class="col d-flex flex-column align-items-center justify-content-center" style="font-family: 'Open Sans',serif">
            <h1 class="text-center mt-5">Welcome to Feedly</h1>
            <p class="text-center">Access all your custom feeds in one place</p>
        </div>
        """;
    return Results.Text(html, "text/html");
});


app.MapGet("/feeds", async (FeedlyRepository repo, ClaimsPrincipal claimsPrincipal) =>
{
    var feeds = await repo.GetFeeds(long.Parse(claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier)!));
    var html1 = feeds.Aggregate(
        """
        <div class="logout container-fluid h-100">
        <div class="row h-100">
        <div class="col-3 d-md-block d-none overflow-y-auto h-100 border-2 border-end logout">
            <p class="text-center mt-2">Your Feeds</p>
                <div class="list-group shadow-lg " id="list-tab" role="tablist">
        """,
        (current, feed) =>
            current + $"""
                       <div class="container" id="feed{feed.Id}">
                       <div class="row">
                       <div type="button" data-bs-toggle="list" class="list-group-item list-group-item-action d-flex" hx-get="/feeds/{feed.Id}" hx-swap="innerHTML" hx-target="#content">
                           <div class="me-auto text-truncate align-items-center d-flex" style="height: 32px">{feed.Title}</div>
                       </div>
                       <button hx-delete="/feeds/{feed.Id}" hx-target="#feed{feed.Id}" hx-swap="delete" type="button" class="btn btn-danger btn-sm deleteFeed d-none">
                           <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor"
                           class="bi bi-x" viewBox="0 0 16 16">
                              <path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z"/>
                           </svg>
                       </button>
                       <button hx-patch="/feeds/share/{feed.Id}" hx-swap="none" class="btn btn-primary btn-sm shareFeed d-none">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="bi bi-share" viewBox="0 0 16 16">
                         <path d="M13.5 1a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3M11 2.5a2.5 2.5 0 1 1 .603 1.628l-6.718 3.12a2.5 2.5 0 0 1 0 1.504l6.718 3.12a2.5 2.5 0 1 1-.488.876l-6.718-3.12a2.5 2.5 0 1 1 0-3.256l6.718-3.12A2.5 2.5 0 0 1 11 2.5m-8.5 4a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3m11 5.5a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3"/>
                       </svg>
                        </button>
                       </div>
                       </div>
                       """
    );

    html1 +=
        """
            </div>
            <div class="d-flex justify-content-around mt-4">
                <button type="button" data-bs-toggle="collapse"
                data-bs-target="#addFeedCollapse" class="btn btn-primary">Add Feed</button>
                <button type="button" class="btn btn-danger" id="deleteFeeds" onclick="toggleDeleteButtons()">Delete Feed</button>
             </div>
             <div class="d-flex justify-content-center mt-4">
                <button type="button" class="btn btn-primary" onclick="toggleShareButtons()" hx-swap="outerHTML">share</button>
            </div>
             <div class="collapse" id="addFeedCollapse">
                <form hx-post="/feeds" hx-include="[id='antiforgeryToken']" hx-swap="beforeend" hx-target="#list-tab" enctype="multipart/form-data">
                    <div class="mb-3">
                        <label for="feedUrl" class="form-label">Feed Url</label>
                        <input type="text" class="form-control" id="feedUrl" name="feedUrl" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Add</button>
                </form>
            </div>
        </div>
            
        <div class="col-md-9 overflow-y-auto h-100 logout" id="content">
            <div id="viewFeed" class="d-flex justify-content-center align-items-center h-100">
                <p class="text-center">Select a feed to view</p>
            </div>
        </div>
        </div>
        </div>


        """;


    return Results.Text(html1, "text/html");
}).RequireAuthorization();

app.MapPost("/feeds", async ([FromForm] string feedUrl, FeedlyRepository repo, ClaimsPrincipal claimsPrincipal) =>
{
    try
    {
        claimsPrincipal.Claims.ToList().ForEach(claim => app.Logger.LogInformation($"{claim.Type}: {claim.Value}"));
        var feed = await FeedReader.ReadAsync(feedUrl);
        var newfeed = new Feed(null, title: feed.Title, feedUrl,
            long.Parse(claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier)!));

        newfeed.Id = await repo.AddFeed(newfeed);


        var html =
            $"""
             <div class="container" id="feed{feed.Id}">
             <div class="row">
             <div type="button" data-bs-toggle="list" class="list-group-item list-group-item-action d-flex" hx-get="/feeds/{feed.Id}" hx-swap="innerHTML" hx-target="#content">
                 <div class="me-auto text-truncate align-items-center d-flex" style="height: 32px">{feed.Title}</div>
             </div>
             <button hx-delete="/feeds/{feed.Id}" hx-target="#feed{feed.Id}" hx-swap="delete" type="button" class="btn btn-danger btn-sm deleteFeed d-none">
                 <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor"
                 class="bi bi-x" viewBox="0 0 16 16">
                    <path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z"/>
                 </svg>
             </button>
             <button hx-patch="/feeds/share/{feed.Id}" hx-swap="none" class="btn btn-primary btn-sm shareFeed d-none">
                  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="bi bi-share" viewBox="0 0 16 16">
               <path d="M13.5 1a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3M11 2.5a2.5 2.5 0 1 1 .603 1.628l-6.718 3.12a2.5 2.5 0 0 1 0 1.504l6.718 3.12a2.5 2.5 0 1 1-.488.876l-6.718-3.12a2.5 2.5 0 1 1 0-3.256l6.718-3.12A2.5 2.5 0 0 1 11 2.5m-8.5 4a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3m11 5.5a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3"/>
             </svg>
              </button>
             </div>
             </div>
             """;
        return Results.Content(html, "text/html");
    }
    catch (Exception e)
    {
        var logger = app.Logger;
        logger.LogError(e, "Error adding feed");
        return Results.UnprocessableEntity("invalid feed url");
    }
}).RequireAuthorization();

app.MapGet("/feeds/{id:long}", async (long id, FeedlyRepository repo, ClaimsPrincipal claimsPrincipal) =>
{
    Feed feed;
    string html;
    if (claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier) is null)
    {
        try
        {
            feed = await repo.GetSharedFeed(id);
        }
        catch (Exception e)
        {
            app.Logger.LogError(e, "Error getting shared feed");
            return Results.Unauthorized();
        }

        html =
            $"""<div id='welcome' hx-get="feeds/{id}" hx-trigger="every 60s" hx-swap='outerHTML' class="overflow-y-scroll h-100">""";
    }
    else
    {
        feed = await repo.GetFeed(id, long.Parse(claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier)!));
        html = $"""<div hx-get="feeds/{id}" hx-trigger="every 60s" hx-swap='outerHTML' class="logout">""";
    }

    var feedContent = await FeedReader.ReadAsync(feed.Url);
    Regex regex = new(@"\p{IsArabic}");

    html = feedContent.Items.Aggregate(html,
        (current, item) =>
        {
            var html = current;
            var titleDirection = regex.IsMatch(item.Title ?? "title") ? "rtl" : "ltr";
            var desDirection = regex.IsMatch(item.Description ?? "description") ? "rtl" : "ltr";
            html += $"""
                         <div class='card mt-2'>
                             <div class='card-body'>
                                 <h5 class='card-title' dir='{titleDirection}'>{item.Title}</h5>
                                 <p class='card-text' dir='{desDirection}'>{item.Description}</p>
                                 <p class='card-text' dir='{titleDirection}'><small class='text-muted'>{item.PublishingDate}</small></p>
                     """;
            if (titleDirection == "rtl")
            {
                html +=
                    $"<div class='d-flex justify-content-end'> <a href='{item.Link}' class='btn btn-primary'>اقرأ المزيد</a></div>";
            }
            else
            {
                html += $"<a href='{item.Link}' class='btn btn-primary'>Read More</a>";
            }

            html +=
                """
                    </div>
                </div>
                """;

            return html;
        }) + "</div>";
    return Results.Content(html, "text/html");
});

app.MapDelete("/feeds/{id:int}", async (int id, FeedlyRepository repo, ClaimsPrincipal claimsPrincipal) =>
{
    try
    {
        await repo.DeleteFeed(id, long.Parse(claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier)!));
        return Results.Ok();
    }
    catch (Exception e)
    {
        var logger = app.Logger;
        logger.LogError(e, "Error deleting feed");
        return Results.Problem("Error deleting feed");
    }
}).RequireAuthorization();

app.MapPatch("/feeds/share/{id:int}", async (int id, FeedlyRepository repo, ClaimsPrincipal claimsPrincipal) =>
{
    try
    {
        await repo.ShareFeed(id, long.Parse(claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier)!));
        return Results.Ok();
    }
    catch (Exception e)
    {
        var logger = app.Logger;
        logger.LogError(e, "Error sharing feed");
        return Results.Problem("Error sharing feed");
    }
}).RequireAuthorization();

app.Run();


internal class Feed(long? id, string title, string url, long userId, long shared = 0)
{
    public long? Id { get; set; } = id;
    public string Title { get; init; } = title;
    public string Url { get; init; } = url;
    public bool Shared { get; set; } = shared == 1;
    public long UserId { get; set; } = userId;
}

internal class User(long? id, string email, string password)
{
    public long? Id { get; set; } = id;
    public string Email { get; init; } = email;
    public string Password { get; set; } = password;
}

internal class FeedlyRepository(string connectionString)
{
    public async Task CreateDatabaseTable()
    {
        await using var connection = new SqliteConnection(connectionString);
        await connection.ExecuteAsync(
            """
            CREATE TABLE IF NOT EXISTS Feeds (
                Id INTEGER PRIMARY KEY,
                Title TEXT NOT NULL,
                Url TEXT NOT NULL,
                UserId INTEGER NOT NULL,
                Shared INTEGER NOT NULL DEFAULT 0 CHECK(Shared IN (0, 1)),
                FOREIGN KEY(UserId) REFERENCES Users(Id)
            );
            CREATE TABLE IF NOT EXISTS Users (
                Id INTEGER PRIMARY KEY,
                Email TEXT NOT NULL,
                Password TEXT NOT NULL
            );
            """
        );
    }

    public async Task<long> AddFeed(Feed feed)
    {
        await using var connection = new SqliteConnection(connectionString);
        var result =
            await connection.QuerySingleAsync<long>(
                "INSERT INTO Feeds (Title, Url, UserId) VALUES (@Title, @Url, @UserId);SELECT last_insert_rowid()",
                feed);
        return result;
    }

    public async Task DeleteFeed(int id, long UserId)
    {
        await using var connection = new SqliteConnection(connectionString);
        await connection.ExecuteAsync("DELETE FROM Feeds WHERE Id = @Id AND UserId = @UserId",
            new { Id = id, UserId });
    }

    public async Task<IEnumerable<Feed>> GetFeeds(long userId)
    {
        await using var connection = new SqliteConnection(connectionString);
        return await connection.QueryAsync<Feed>("SELECT * FROM Feeds WHERE UserId = @UserId",
            new { UserId = userId });
    }

    public async Task<Feed> GetFeed(long id, long userId)
    {
        await using var connection = new SqliteConnection(connectionString);
        return await connection.QuerySingleAsync<Feed>("SELECT * FROM Feeds WHERE Id = @Id AND UserId = @UserId",
            new { Id = id, UserId = userId });
    }

    public async Task<Feed> GetSharedFeed(long id)
    {
        await using var connection = new SqliteConnection(connectionString);
        return await connection.QuerySingleAsync<Feed>("SELECT * FROM Feeds WHERE Id = @Id AND Shared = 1",
            new { Id = id });
    }

    public async Task ShareFeed(long id, long userId)
    {
        await using var connection = new SqliteConnection(connectionString);
        await connection.ExecuteAsync("UPDATE Feeds SET Shared = 1 WHERE Id = @Id AND UserId = @UserId",
            new { Id = id, UserId = userId });
    }

    public async Task<User?> GetUser(string email)
    {
        await using var connection = new SqliteConnection(connectionString);
        return await connection.QuerySingleOrDefaultAsync<User>("SELECT * FROM Users WHERE Email = @Email",
            new { Email = email });
    }

    public async Task<long> AddUser(User user)
    {
        await using var connection = new SqliteConnection(connectionString);
        var result =
            await connection.QuerySingleAsync<long>(
                "INSERT INTO Users (Email, Password) VALUES (@Email, @Password);SELECT last_insert_rowid()", user);
        return result;
    }
}