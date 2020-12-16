# AuthSamples.Cookies
=================

Sample demonstrating cookie authentication:
1. Run the app and click on the MyClaims tab, this should trigger a redirect to login.
2. Login with any username and password, the sample just validates that any values are provided.
3. You should be redirected back to /Home/MyClaims which will output a few user claims.

Startup.cs and Controllers/AccountController.cs are the most interesting classes in the sample.

# �ο�����
�ٷ��ĵ���https://docs.microsoft.com/en-us/aspnet/core/security/authentication/cookie?view=aspnetcore-5.0
�ٷ�ʾ����https://github.com/dotnet/AspNetCore.Docs/tree/master/aspnetcore/security/authentication/cookie/samples

# cookie��֤����������
https://blog.csdn.net/u010476739/article/details/104474850

�������ط����Խ������ã�һ������startup��AddCookie()���ã���һ������/Account/LoginAction�е�HttpContext.SignInAsync()��������á�
1.1 AddCookie()������
��������Ҫ����������ExpireTimeSpan�ͣ�
ExpireTimeSpan��ǰ�߱�ʾһ�ε�¼��Ч�����ޣ�Ĭ����14�죬
SlidingExpiration�����߱�ʾ�Ƿ����û������ڣ������������ô��cookie�쵽�ڵ�ʱ������°䷢��cookie��


# �ỰCookie �� �־�Cookie
https://www.cnblogs.com/tdfblog/p/aspnet-core-security-authentication-cookie.html

IsPersistentĬ��Ϊfalse����ʱ��Cookie�ǻỰCookie���ر��������ᱻɾ����
��IsPersistent����Ϊtrue,Cookie��ɳ־�Cookie���ر�������󲻻ᱻɾ�������ǵ��ں��ɾ����
�ͻ��˿����á���ס�ҡ���IsPersistent�󶨣��´ε�¼���Բ��������û�������


```C#
                var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Cookies", "user", "role"));
                //await HttpContext.SignInAsync(claimsPrincipal);
                await HttpContext.SignInAsync(Startup.AuthenticationScheme_Cookie, claimsPrincipal, new AuthenticationProperties
                {
                    /*
                     * IsPersistentĬ��Ϊfalse����ʱ��Cookie�ǻỰCookie���ر��������ᱻɾ����
                     * ��IsPersistent����Ϊtrue,Cookie��ɳ־�Cookie���ر�������󲻻ᱻɾ�������ǵ��ں��ɾ����
                     * �ͻ��˿����á���ס�ҡ���IsPersistent�󶨣��´ε�¼���Բ��������û�������
                     */
                    IsPersistent = true 
                }) ;
```
AuthenticationPropertiesһЩ����
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