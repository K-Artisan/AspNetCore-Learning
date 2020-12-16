# AuthSamples.Cookies
=================

Sample demonstrating cookie authentication:
1. Run the app and click on the MyClaims tab, this should trigger a redirect to login.
2. Login with any username and password, the sample just validates that any values are provided.
3. You should be redirected back to /Home/MyClaims which will output a few user claims.

Startup.cs and Controllers/AccountController.cs are the most interesting classes in the sample.

# 参考资料
官方文档：https://docs.microsoft.com/en-us/aspnet/core/security/authentication/cookie?view=aspnetcore-5.0
官方示例：https://github.com/dotnet/AspNetCore.Docs/tree/master/aspnetcore/security/authentication/cookie/samples

# cookie认证的期限配置
https://blog.csdn.net/u010476739/article/details/104474850

有两个地方可以进行配置，一个是在startup的AddCookie()设置，另一个是在/Account/LoginAction中的HttpContext.SignInAsync()里进行设置。
1.1 AddCookie()配置项
在这里主要配置两个：ExpireTimeSpan和，
ExpireTimeSpan：前者表示一次登录有效的期限，默认是14天，
SlidingExpiration：后者表示是否启用滑动窗口，如果启用了那么在cookie快到期的时候会重新颁发个cookie。


# 会话Cookie 和 持久Cookie
https://www.cnblogs.com/tdfblog/p/aspnet-core-security-authentication-cookie.html

IsPersistent默认为false，这时的Cookie是会话Cookie，关闭浏览器后会被删除。
将IsPersistent设置为true,Cookie变成持久Cookie，关闭浏览器后不会被删除，除非到期后才删除。
客户端可设置“记住我”与IsPersistent绑定，下次登录可以不用输入用户和密码


```C#
                var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Cookies", "user", "role"));
                //await HttpContext.SignInAsync(claimsPrincipal);
                await HttpContext.SignInAsync(Startup.AuthenticationScheme_Cookie, claimsPrincipal, new AuthenticationProperties
                {
                    /*
                     * IsPersistent默认为false，这时的Cookie是会话Cookie，关闭浏览器后会被删除。
                     * 将IsPersistent设置为true,Cookie变成持久Cookie，关闭浏览器后不会被删除，除非到期后才删除。
                     * 客户端可设置“记住我”与IsPersistent绑定，下次登录可以不用输入用户和密码
                     */
                    IsPersistent = true 
                }) ;
```
AuthenticationProperties一些配置
```C#
var authProperties = new AuthenticationProperties
{
    //AllowRefresh = <bool>,
    // Refreshing the authentication session should be allowed.

    //ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),
    // The time at which the authentication ticket expires. A 
    // value set here overrides the ExpireTimeSpan option of 
    // CookieAuthenticationOptions set with AddCookie.

    //IsPersistent = true,
    // Whether the authentication session is persisted across 
    // multiple requests. When used with cookies, controls
    // whether the cookie's lifetime is absolute (matching the
    // lifetime of the authentication ticket) or session-based.

    //IssuedUtc = <DateTimeOffset>,
    // The time at which the authentication ticket was issued.

    //RedirectUri = <string>
    // The full path or absolute URI to be used as an http 
    // redirect response value.
};

```