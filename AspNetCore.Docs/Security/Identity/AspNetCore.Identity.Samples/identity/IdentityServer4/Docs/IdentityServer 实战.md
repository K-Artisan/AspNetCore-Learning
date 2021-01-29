# IdentityServer 实战

[TOC]

## Authorization Code 模式

参考资料：

 https://chsakell.com/2019/03/11/asp-net-core-identity-series-oauth-2-0-openid-connect-identityserver/



### 如何检验授权流程

#### 前端应用程序

使用 a javascript library named *oidc-client*  

[*oidc-client* ](https://cdnjs.cloudflare.com/ajax/libs/oidc-client/1.6.1/oidc-client.js)

不会，略

#### 浏览器客户端

- 把这个三个项目同时启动

- 打开浏览器，在地址输入如下地址：

  ```http
  http://localhost:5005/connect/authorize?client_id=AspNetCoreIdentity&redirect_uri=http://localhost:5000&response_type=code&scope=openid profile SocialAPI&state=be1916720a2e4585998ae504d43a3c7&code_challenge=pxUY7Dldu3UtT1BM4YGNLEeK45tweexRqbTk79J611o&code_challenge_method=S256
  ```

​     

输入上述地址后，重定向到登录页面：

```http
http://localhost:5005/Account/Login?ReturnUrl=/connect/authorize/callback?client_id=AspNetCoreIdentity&redirect_uri=http://localhost:5000&response_type=code&scope=openid profile SocialAPI&state=be1916720a2e4585998ae504d43a3c7&code_challenge=pxUY7Dldu3UtT1BM4YGNLEeK45tweexRqbTk79J611o&code_challenge_method=S256
```



![1611934854026](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611934854026.png)输入账号和密码

chsakell

$AspNetIdentity10$



- 输入账号和密码，跳转到授权页面：

  ```http
  http://localhost:5005/consent?returnUrl=%2Fconnect%2Fauthorize%2Fcallback%3Fclient_id%3DAspNetCoreIdentity%26redirect_uri%3Dhttp%253A%252F%252Flocalhost%253A5000%26response_type%3Dcode%26scope%3Dopenid%2520profile%2520SocialAPI%26state%3Dbe1916720a2e4585998ae504d43a3c7%26code_challenge%3DpxUY7Dldu3UtT1BM4YGNLEeK45tweexRqbTk79J611o%26code_challenge_method%3DS256
  ```

  <img src="images/IdentityServer%20%E5%AE%9E%E6%88%98/1611935069951.png" alt="1611935069951" style="zoom:150%;" />

点击【Yes, Allow】进行授权

- 授权成功后，会跳转到

  ![1611935377362](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611935377362.png)

  然后又瞬间跳转会网站

  ```http
  http://localhost:5000/?code=bjVLsoQc-_XjUGWS4zsP6jA_D1wNUIyLbxUvYZB1OTY&scope=openid profile SocialAPI&state=be1916720a2e4585998ae504d43a3c7&session_state=RVBo548y26jFGbZrnH3nN8SIXy9iGhoHHYa5jLhm4Po.z0jD6A6dgSCzpBGP8aQwWA
  ```

  从这个Url地址，可以从参数**code**提取出 **authorization code** ：

  ```md
  bjVLsoQc-_XjUGWS4zsP6jA_D1wNUIyLbxUvYZB1OTY
  ```

  

- 客户端请求 **access token**  

  打开这个授权服务器的配置地址，

    http://localhost:5005/.well-known/openid-configuration 

  返回信息：

  ```json
  {
    "issuer": "http://localhost:5005",
    "jwks_uri": "http://localhost:5005/.well-known/openid-configuration/jwks",
    "authorization_endpoint": "http://localhost:5005/connect/authorize",
    "token_endpoint": "http://localhost:5005/connect/token",
    "userinfo_endpoint": "http://localhost:5005/connect/userinfo",
    "end_session_endpoint": "http://localhost:5005/connect/endsession",
    "check_session_iframe": "http://localhost:5005/connect/checksession",
    "revocation_endpoint": "http://localhost:5005/connect/revocation",
    "introspection_endpoint": "http://localhost:5005/connect/introspect",
    "device_authorization_endpoint": "http://localhost:5005/connect/deviceauthorization",
    "frontchannel_logout_supported": true,
    "frontchannel_logout_session_supported": true,
    "backchannel_logout_supported": true,
    "backchannel_logout_session_supported": true,
    "scopes_supported": [
      "profile",
      "openid",
      "SocialAPI",
      "offline_access"
    ],
    "claims_supported": [
      "nickname",
      "middle_name",
      "given_name",
      "family_name",
      "name",
      "preferred_username",
      "profile",
      "picture",
      "website",
      "gender",
      "birthdate",
      "zoneinfo",
      "locale",
      "updated_at",
      "sub"
    ],
    "grant_types_supported": [
      "authorization_code",
      "client_credentials",
      "refresh_token",
      "implicit",
      "password",
      "urn:ietf:params:oauth:grant-type:device_code"
    ],
    "response_types_supported": [
      "code",
      "token",
      "id_token",
      "id_token token",
      "code id_token",
      "code token",
      "code id_token token"
    ],
    "response_modes_supported": [
      "form_post",
      "query",
      "fragment"
    ],
    "token_endpoint_auth_methods_supported": [
      "client_secret_basic",
      "client_secret_post"
    ],
    "id_token_signing_alg_values_supported": [
      "RS256"
    ],
    "subject_types_supported": [
      "public"
    ],
    "code_challenge_methods_supported": [
      "plain",
      "S256"
    ],
    "request_parameter_supported": true
  }
  ```

  

  

  ![1611936598767](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611936598767.png)

  ```http
  http://localhost:5005/connect/token
  ```

  这就是请求**access_token**的地址

  

- 至此不知道怎么使用PostMan获取**access_token**了

  改用全部使用PostMan获取**access_token**

#### 使用PostMan

##### 访问受保护API

- 新建一个GET请求

  ![1611940295498](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611940295498.png)



输入地址：GET

```htpp
http://localhost:5010/api/contacts
```

切换到【Authorization】选项卡，依照图进行配置,下面是对这些配置的说明：

我们先看下在项目【IdentityServer】中， 文件`Conifg.cs`中客户端的定义

```C#
   public static class Config
    {
        public static IEnumerable<Client> GetClients()
        {
            return new List<Client>
            {
                new Client
                {
                    ClientId = "AspNetCoreIdentity",
                    ClientName = "AspNetCoreIdentity Client",
                    AllowedGrantTypes = GrantTypes.Code,
                    RequirePkce = true,
                    RequireClientSecret = false,

                    RedirectUris =           { "http://localhost:5000" },
                    PostLogoutRedirectUris = { "http://localhost:5000" },
                    AllowedCorsOrigins =     { "http://localhost:5000" },

                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "SocialAPI"
                    }
                }
            };
        }
```

- 步骤5：  **Grant Type**  为什么选【Anthorization code （With PKCE）】？

  答：

  ```C#
  RequirePkce = true,
  ```

  

- **Client Secret** 为什么不填

  答：

  ```C#
  RequireClientSecret = false,
  ```

  

-  **Code Challenge Method**  为什么选**SHA-256**

  不知道，反正使用PLAN就不行

  https://blog.csdn.net/weixin_34415923/article/details/89691037
  
-  Code Verifier 

  参见：https://blog.csdn.net/weixin_34415923/article/details/89691037

  ![1611941546891](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611941546891.png)

-  Scope ：

  ```C#
                      AllowedScopes =
                      {
                          IdentityServerConstants.StandardScopes.OpenId,
                          IdentityServerConstants.StandardScopes.Profile,
                          "SocialAPI"
                      }
  ```

  ```C#
          public static class StandardScopes
          {
              //
              // 摘要:
              //     REQUIRED. Informs the Authorization Server that the Client is making an OpenID
              //     Connect request. If the openid scope value is not present, the behavior is entirely
              //     unspecified.
              public const string OpenId = "openid";
              //
              // 摘要:
              //     OPTIONAL. This scope value requests access to the End-User's default profile
              //     Claims, which are: name, family_name, given_name, middle_name, nickname, preferred_username,
              //     profile, picture, website, gender, birthdate, zoneinfo, locale, and updated_at.
              public const string Profile = "profile";
  
          }
  ```

  

- 点击生成access_token按钮

  点击生成access_token按钮 ，会有一个弹框

  ![1611941843487](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611941843487.png)

  

  这PostMan的一个功能，输入账号和密码

  chsakell

  $AspNetIdentity10$

  ![1611947137532](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611947137532.png)

  点击【Yes, Allow】,

  ![1611935377362](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611935377362.png)

  ![1611941969930](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611941969930.png)
  
  看到返回的信息
  
  包括：
  
  

![1611942027695](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611942027695.png)

 Id_token:

![1611942156663](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611942156663.png)

总之返回信息如下:

 **expires_in** ：3600

 **scope** ： openid profile SocialAPI 

**Token Type** ： Bearer

 **Access Token** ：

```json
eyJhbGciOiJSUzI1NiIsImtpZCI6ImtHNFpINnlhVENZdkxVUWNtbFVndUEiLCJ0eXAiOiJhdCtqd3QifQ.eyJuYmYiOjE2MTE5NDE5MzQsImV4cCI6MTYxMTk0NTUzNCwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo1MDA1IiwiYXVkIjoiU29jaWFsQVBJIiwiY2xpZW50X2lkIjoiQXNwTmV0Q29yZUlkZW50aXR5Iiwic3ViIjoiYTQ3ZjQ4ZTktMTgxOC00NmZkLWEyZTAtYjA5ZTk1ZDQzOTc3IiwiYXV0aF90aW1lIjoxNjExOTQxOTMzLCJpZHAiOiJsb2NhbCIsInNjb3BlIjpbInByb2ZpbGUiLCJvcGVuaWQiLCJTb2NpYWxBUEkiXSwiYW1yIjpbInB3ZCJdfQ.C1AkdHUl43EYEKJN9OLLWwLuYtLrNzhqF0RZ-4b56UP_BLVaVyKT9fK8M_1G1SBxTRHr7bu1CJFPCetemC4pRH61Q61dnII2dgWZc5rYriqng43xY56z-Mk6h5zO-o6FLVlGrpnxc8F5M7EzTNtwrNJZYObAQa_mIOgfrWEGeivgQhLGzRx4Schr8Z-hURR-H0n_lc2Wc5Ohz0NDS4mwFx4GydQRbWBaQ5xytR9LlUIBaOR9qmqzmpVmepK08QvHQlOp-aA5W7YhV7N_a6JyyrJtySz5h2d2Ja0EkCFQuRa3nkadiv6cvY4RjAvygLPu4rhpAYQ4EK2MMDqnezkS2w
```

点击[https://jwt.ms/](https://jwt.ms/)或者[jwt.io/](jwt.io/)解析下Access Token,内容如下

```json
{
  "alg": "RS256",
  "kid": "kG4ZH6yaTCYvLUQcmlUguA",
  "typ": "at+jwt"
}.{
  "nbf": 1611941934,
  "exp": 1611945534,
  "iss": "http://localhost:5005",
  "aud": "SocialAPI",
  "client_id": "AspNetCoreIdentity",
  "sub": "a47f48e9-1818-46fd-a2e0-b09e95d43977",
  "auth_time": 1611941933,
  "idp": "local",
  "scope": [
    "profile",
    "openid",
    "SocialAPI"
  ],
  "amr": [
    "pwd"
  ]
}.[Signature]
```



 **id_token** :

```json
eyJhbGciOiJSUzI1NiIsImtpZCI6ImtHNFpINnlhVENZdkxVUWNtbFVndUEiLCJ0eXAiOiJKV1QifQ.eyJuYmYiOjE2MTE5NDE5MzQsImV4cCI6MTYxMTk0MjIzNCwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo1MDA1IiwiYXVkIjoiQXNwTmV0Q29yZUlkZW50aXR5IiwiaWF0IjoxNjExOTQxOTM0LCJhdF9oYXNoIjoiTktVNERNb0FNcUp3MzNIODRFS05EQSIsInNfaGFzaCI6InNXM3JQaUN0cDJpSzFadGd6dGVTNUEiLCJzaWQiOiJkUkU2OFRJTVpmNmxJSHNzUkpSSXhBIiwic3ViIjoiYTQ3ZjQ4ZTktMTgxOC00NmZkLWEyZTAtYjA5ZTk1ZDQzOTc3IiwiYXV0aF90aW1lIjoxNjExOTQxOTMzLCJpZHAiOiJsb2NhbCIsImFtciI6WyJwd2QiXX0.lIh3GrH95HiOL6Tn_3UvVvA7qbR6D5_1WP42K1E4lduD_ZLj9U2arEzM2F-hpX-WzuA_O-Dd88dcXNHMbBWbmqcsMAEKjVaEh_sHBC6jZiHqC2yeNhtwwSOseDuZmaVAEFLembXIqNSoqkTuJdDKFaNuP9EF9F294KT4eIlGIBz-b5FQxPJvU4A07o8Vswma13DMuPGeWJQvbocFbWbaqAnvGxqCQyxqfRBfNiwcQJAAw_0UjotG2NS4iaEpp4avJstStKy6oEo8ZBr9wS2lWzh133BTQnVqnhvObWVLxfpIPm55EF8AW_RxuKDpAN5Kj2oRs77h0iVsAuQ6UnPX6w
```

解析如下：

```json
{
  "alg": "RS256",
  "kid": "kG4ZH6yaTCYvLUQcmlUguA",
  "typ": "JWT"
}.{
  "nbf": 1611941934,
  "exp": 1611942234,
  "iss": "http://localhost:5005",
  "aud": "AspNetCoreIdentity",
  "iat": 1611941934,
  "at_hash": "NKU4DMoAMqJw33H84EKNDA",
  "s_hash": "sW3rPiCtp2iK1ZtgzteS5A",
  "sid": "dRE68TIMZf6lIHssRJRIxA",
  "sub": "a47f48e9-1818-46fd-a2e0-b09e95d43977",
  "auth_time": 1611941933,
  "idp": "local",
  "amr": [
    "pwd"
  ]
}.[Signature]
```



- ![1611942866063](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611942866063.png)

返回在的项目【SocialNetwork.API】的**受保护的API数据**：

```json
[
    {
        "id": "fcf1bd4f-545b-4ace-8cdd-82b011b59c33",
        "name": "Francesca Fenton",
        "username": "Fenton25",
        "email": "francesca@example.com"
    },
    {
        "id": "0f04ba22-6281-4986-9d48-784f7ebd94f5",
        "name": "Pierce North",
        "username": "Pierce",
        "email": "pierce@example.com"
    },
    {
        "id": "02feb88d-ba0b-4467-a0af-8f78aadcae8d",
        "name": "Marta Grimes",
        "username": "GrimesX",
        "email": "marta@example.com"
    },
    {
        "id": "bf803ff6-cf6c-4556-9fff-8f1e935bab55",
        "name": "Margie Kearney",
        "username": "Kearney20",
        "email": "margie@example.com"
    }
]
```

项目【SocialNetwork.API】啥也没做，只是添加了JwtBearer认证：

```C#
             public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            services.AddAuthorization();

            services.AddAuthentication("Bearer")
              .AddJwtBearer("Bearer", options =>
              {
                  options.Authority = "http://localhost:5005";
                  options.RequireHttpsMetadata = false;

                  //必须与我们之前定义的API资源名称相匹配
                  options.Audience = "SocialAPI";
              });

        }


        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            //......
            app.UseAuthentication();
            app.UseAuthorization();
            //......
        }
```



提醒：

如果已经输入过账号和密码进行了授权，再次点击 【Get New Access Token】按钮，是不需要再跳转到登录页面

![1611941843487](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611941843487.png)

而是直接进行生成access_token的等待过程，

如果要再次进入登录页面，需要如下图所示，删除cookie

![1611945248116](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611945248116.png)

![1611945286387](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611945286387.png)



##### 访问用户信息

```
Request URL: http://localhost:5005/connect/userinfo
Request Method: GET
```

```
Authorization: Bearer 
```

![1611944324061](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611944324061.png)

即：

```json
{
  "sub": "a47f48e9-1818-46fd-a2e0-b09e95d43977",
  "name": "Chris Sakellarios",
  "given_name": "Christos",
  "family_name": "Sakellarios",
  "website": "https://chsakell.com",
  "preferred_username": "chsakell"
}
```

这些信息来自，项目【IdentityServer】，文件`DatabaseInitializer`初始化数据库数据时创建的用户信息

IdentityServer/DatabaseInitializer.cs

```C#
 var userManager = provider.GetRequiredService<UserManager<IdentityUser>>();
            var chsakell = userManager.FindByNameAsync("chsakell").Result;
            if (chsakell == null)
            {
                chsakell = new IdentityUser
                {
                    UserName = "chsakell"
                };
                var result = userManager.CreateAsync(chsakell, "$AspNetIdentity10$").Result;
                if (!result.Succeeded)
                {
                    throw new Exception(result.Errors.First().Description);
                }

                chsakell = userManager.FindByNameAsync("chsakell").Result;

                result = userManager.AddClaimsAsync(chsakell, new Claim[]{
                    new Claim(JwtClaimTypes.Name, "Chris Sakellarios"),
                    new Claim(JwtClaimTypes.GivenName, "Christos"),
                    new Claim(JwtClaimTypes.FamilyName, "Sakellarios"),
                    new Claim(JwtClaimTypes.Email, "chsakellsblog@blog.com"),
                    new Claim(JwtClaimTypes.EmailVerified, "true", ClaimValueTypes.Boolean),
                    new Claim(JwtClaimTypes.WebSite, "https://chsakell.com"),
                    new Claim(JwtClaimTypes.Address, @"{ 'street_address': 'localhost 10', 'postal_code': 11146, 'country': 'Greece' }", 
                        IdentityServer4.IdentityServerConstants.ClaimValueTypes.Json)
                }).Result;
```

数据库中存储在 如下两张表中

```sql
SELECT * FROM [IdentityServerDb].[dbo].[AspNetUsers];
SELECT * FROM [IdentityServerDb].[dbo].[AspNetUserClaims];
```

![1611944825239](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611944825239.png)



### 取消授权

登录访问：http://localhost:5005/grants

![1611943427033](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611943427033.png)

有个管理授权页面：

Revoke Access： 撤销访问 



#### 授权存储

授权记录是存储在[IdentityServerDb].[dbo].[PersistedGrants]中

```sql
SELECT TOP 1000 [Key]
      ,[Type]
      ,[SubjectId]
      ,[ClientId]
      ,[CreationTime]
      ,[Expiration]
      ,[Data]
  FROM [IdentityServerDb].[dbo].[PersistedGrants]
```

![1611946488866](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611946488866.png)

其中，Data列的值为：

```json
{
  "SubjectId": "a47f48e9-1818-46fd-a2e0-b09e95d43977",
  "ClientId": "AspNetCoreIdentity",
  "Scopes": [
    "openid",
    "profile",
    "SocialAPI"
  ],
  "CreationTime": "2021-01-29T15:47:29Z",
  "Expiration": null
}
```

点击【Revoke Access】取消授权后，这行数据会被删除：

![1611946593360](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611946593360.png)

奇怪的是，取消授权后，使用**未过期的access_token**，能继续访问受保护API，意思是，取消授权对已经授权的access_token爱莫能助。

#### 重新授权

取消授权后，可重新获取授权，流程跟之前一样，账号密码登录，确认授权，

http://localhost:5005/Grants

![1611947541337](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611947541337.png)



数据库又有了授权记录

![1611947390914](images/IdentityServer%20%E5%AE%9E%E6%88%98/1611947390914.png)

其中，Data列的值为：

```json
{
  "SubjectId": "a47f48e9-1818-46fd-a2e0-b09e95d43977",
  "ClientId": "AspNetCoreIdentity",
  "Scopes": [
    "openid",
    "profile",
    "SocialAPI"
  ],
  "CreationTime": "2021-01-29T19:06:07Z",
  "Expiration": null
}
```



**存疑**：Key和SubjectId两次授权后都是一样的，为何？

