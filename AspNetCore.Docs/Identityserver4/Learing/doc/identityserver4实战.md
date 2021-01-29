[TOC]

# identityserver4实战

## 基础概念

参考资料：

[identityServer4 知多少](https://www.cnblogs.com/sheng-jie/p/9430920.html)

[IdentityServer4 中文文档与实战（添加了PPT资料）](https://www.cnblogs.com/stulzq/p/8119928.html)

[OAuth 2.0, OpenID Connect & IdentityServer](https://chsakell.com/2019/03/11/asp-net-core-identity-series-oauth-2-0-openid-connect-identityserver/)



### OpenId

简而言之：**OpenId用于身份认证（Authentication）**



### OAuth 2.0

简而言之：**OAuth2.0 用于授权（Authorization）**

关于OAuth2.0参考：

[OAuth2.0 知多少](https://www.cnblogs.com/sheng-jie/p/6564520.html)

[OAuth2.0简介](https://www.bilibili.com/video/BV16b411k7yM?p=1)



OAuth协议的设计目的是：让最终用户通过OAuth将他们在受保护资源上的部分权限委托给客户端应用，使客户端应用代表他们执行操作。为实现这一点，OAuth在系统中引入了另外一个组件：授权服务器。

![image-20201114181505813](images/identityserver4%E5%AE%9E%E6%88%98/image-20201114181505813.png)

受保护资源依赖授权服务器向客户端颁发专用的安全凭据——OAuth访问令牌。为了获取令牌，客户端首先将资源拥有者引导至授权服务器，请求资源拥有者为其授权。授权服务器先对资源拥有者进行身份认证，然后一般会让资源拥有者选择是否对客户端授权。客户端可以请求授权功能或权限范围的子集，该子集可能会被资源拥有者进一步缩小。一旦授权请求被许可，客户端就可以向授权服务器请求访问令牌。按照资源拥有者的许可，客户端可以使用该令牌对受保护资源上的API进行访问



OAuth是一个应用广泛的安全标准，它提供了一种安全访问受保护资源的方式，特别适用于Web API。
OAuth关注的是如何获取令牌和如何使用令牌。
OAuth是一个委托协议，提供跨系统授权的方案。

### OpenId Connect

简而言之：**OpenId Connect = OIDC = Authentication + Authorization + OAuth2.0**。

[OpenId Connect简介](https://www.bilibili.com/video/BV16b411k7yM?p=3)



### 《OAuth2实战》

#### 为什么OAuth 2.0不是身份认证协议

首先，我们需要弄清楚一个根本问题：什么是身份认证？在当前语境下，身份认证会告诉应用，当前的用户是谁以及是否正在使用此应用。它属于安全架构的一部分，通常通过让用户提供一些凭据（如用户名和密码）给客户端，来证明用户的身份是真实的。实际的身份认证协议可能还会告诉你一些其他的用户身份属性，比如唯一标识符、邮箱地址以及应用向用户打招呼时使用的名字。

然而，OAuth 2.0并不能告诉应用这些信息。OAuth 2.0本身不提供关于用户的任何信息，也不关心用户如何证明身份，甚至不关心用户是否存在。对于OAuth 2.0客户端而言，它只是请求令牌、获取令牌、最终使用该令牌访问某API。至于是谁对应用授权，或者是否有用户存在，它都一无所知。



**尝试使用OAuth构建身份认证协议，但并不可行**

我们要如何基于OAuth构建一个身份认证协议呢？首先，需要将OAuth 2.0中的各方恰当地映射到身份认证事务的各方。在OAuth 2.0事务中，资源拥有者向客户端授权，让它从授权服务器得到访问令牌，客户端使用该访问令牌可以访问受保护资源。在身份认证事务中，最终用户使用身份提供方（identity provider，IdP）登录依赖方（relying party，RP）。

![image-20201115113527537](images/identityserver4%E5%AE%9E%E6%88%98/image-20201115113527537.png)



#### **使用OAuth 2.0进行身份认证的常见陷阱**

我们已经证明了在OAuth之上构建身份认证协议是可行的，但在实施过程中往往存在很多陷阱。在身份提供方和身份使用方这两边都有可能犯错，而且很多情况下都源于对协议各部分描述的误解。

1. 将访问令牌作为身份认证的证明

2. 将对受保护API的访问作为身份认证的证明

3. 访问令牌注入

4. 缺乏目标受众限制

5. 无效用户信息注入

6. 不同身份提供者的协议各不相同

   基于OAuth 2.0的身份API的一个最大的问题是，不同的身份提供者实现的身份API在细节上必然不同，即使它们都以完全符合标准的OAuth为基础。例如，一个身份提供者使用user_id字段表示用户的唯一标识符，而另一个身份提供者使用的是sub。虽然这些字段在语义上是等效的，但在代码中需要使用不同的分支进行处理。虽然在每个身份提供者上的授权过程可能都是相同的，但身份认证信息的传输可能不相同。

   所以，要缓解这一问题，身份提供者应该统一使用一个以OAuth为基础的标准身份认证协议。这样一来，不管身份信息来自何处，它们的传输方式都是一样的。那么，是否存在这样的标准呢？

#### OpenID Connect：一个基于OAuth 2.0的认证和身份标准

​       **OpenID Connect**是一个开放标准，由OpenID基金会于2014年2月发布。它定义了一种使用**OAuth 2.0**执行用户身份认证的互通方式。由于该协议的设计具有互通性，一个OpenID客户端应用可以使用同一套协议语言与不同的身份提供者交互，而不需要为每一个身份提供者实现一套有细微差别的协议。

##### ID令牌

OpenID Connect的ID令牌是一个经过签名的JWT，它与普通的OAuth访问令牌一起提供给客户端应用。与访问令牌不同的是，ID令牌是发送给RP的，并且要被它解析。
与在第11章生成的已签名访问令牌一样，ID令牌包含一组关于身份认证会话的声明，包括一个用户标识符（sub）、颁发给该令牌的身份提供者标识符（iss），以及该令牌的目标客户端标识符（aud）。另外，ID令牌还包含令牌本身的有效时间窗口信息（使用的是exp和iat声明），以及其他需要传递给客户端的关于身份认证上下文的信息。例如，令牌可以指明用户在多久以前使用主要身份认证机制认证过（auth_time），或者在IdP上使用的主要身份认证的类型（acr）。ID令牌还可以包含其他声明，可以是第11章列出的标准JWT声明，也可以是OpenID Connect协议的扩展声明。表13-1用粗体表示的声明是必须提供的。表 13-1　ID令牌中的声明

![image-20201115113302280](images/identityserver4%E5%AE%9E%E6%88%98/image-20201115113302280.png)



ID令牌是通过在令牌端点响应中增加id_token成员来颁发的，是在访问令牌基础上的补充，而不是替换访问令牌。

```json
{
  "access_token": "987tghjkiu6trfghjuytrghj",
  "token_type": "Bearer",
  "id_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDEvIiwic3ViIjoiOVhFMy1KSTM0LTAwMTMyQSIsImF1ZCI6Im9hdXRoLWNsaWVudC0xIiwiZXhwIjoxNDQwOTg3NTYxLCJpYXQiOjE0NDA5ODY1NjF9.LC5XJDhxhA5BLcT3VdhyxmMf6EmlFM_TpgL4qycbHy7JYsO6j1pGUBmAiXTO4whK1qlUdjR5kUm ICcYa5foJUfdT9xFGDtQhRcG3dOg2oxhX2r7nhCjzUnOIebr5POySGQ8ljT0cLm45edv_rO5fSVPdwYGSa7QGdhB0bJ8KJ__RsyKB707n09y1d92ALwAfaQVoyCjYB0uiZM9Jb8yHsvyMEudvSD5urRuHnGny8YlGDIofP6SXh51TlR7ST7R7h9f4Pa0lD9SXEzGUG816HjIFOcD4aAJXxn_QMlRGSfL8NlIz29PrZ2xqg8w2w84hBQcgchAmj1TvaT8ogg6w"
}
```

```json
{
  "typ": "JWT",
  "alg": "RS256"
}.{
  "iss": "http://localhost:9001/",
  "sub": "9XE3-JI34-00132A",
  "aud": "oauth-client-1",
  "exp": 1440987561,
  "iat": 1440986561
}.[Signature]
```

##### UserInfo端点

ID令牌已经包含处理身份认证事件所需的所有信息，足以让OpenID Connect客户端成功登录。

向UserInfo端点发送的请求是简单的HTTP GET和POST请求，并且需要附带上访问令牌（不是ID令牌）以获得权限。虽然与OpenID Connect的很多请求一样，可以使用一些高级的方法，但普通的请求是不带输入参数的。UserInfo端点的受保护资源是这样设计的：系统中所有用户对应同一个资源，而不是为每一个用户分配不同的资源URI。IdP会通过解析**访问令牌**的内容来确定所请求的是哪个用户。

```md
T /userinfo HTTP/1.1
Host: localhost:9002
Accept: application/j
```

由UserInfo端点返回的响应是一个JSON对象，包含关于用户的声明。这些声明往往不易发生变化，所以一般会将UserInfo端点的调用结果缓存下来，而不会在每一次身份认证请求时都去获取。如果使用OpenID Connect的高级功能，得到的UserInfo响应有可能是一个经过签名或加密的JWT。

```json
HTTP/1.1 200 OK
Content-type: application/json

{
  "sub": "9XE3-JI34-00132A",
  "preferred_username": "alice",
  "name": "Alice",
  "email": "alice.wonderland@example.com",
  "email_verified": true
}
```

OpenID Connect使用一个特殊的权限范围值openid来控制对UserInfo端点的访问。OpenID Connect定义了一组标准化的OAuth权限范围，对应于用户属性的子集（profile、email、phone、address，参见表13-2），允许通过普通的OAuth事务来请求身份认证所需的所有信息。OpenID Connect规范对每个权限范围以及它们所对应的属性都进行了更详细的说明。表 13-2　OAuth权限范围与OpenID Connect UserInfo声明之间的对应关系

![image-20201115122656466](images/identityserver4%E5%AE%9E%E6%88%98/image-20201115122656466.png)





### 术语解析

![2799767-00eec4bc3482dd66](images/identityserver4%E5%AE%9E%E6%88%98/2799767-00eec4bc3482dd66.png)

了解完OpenId Connect和OAuth2.0的基本概念，我们再来梳理下涉及到的相关术语：

1. User：用户
2. Client：客户端
3. Resources：Identity Data（身份数据）、Apis
4. Identity Server：认证授权服务器
5. Token：Access Token（访问令牌）和 Identity Token（身份令牌）

可参考：[ASP.NET Core的身份认证框架IdentityServer4（3）-术语的解释 ](https://www.cnblogs.com/stulzq/p/7487734.html)



> - **资源拥有者**有权访问API，并能将API访问权限委托出去。资源拥有者一般是能使用浏览器的人。
>
> - **受保护资源**是资源拥有者有权限访问的组件。这样的组件有多种形式，但大多数情况下是某种形式的Web API。虽然“资源”听起来就像是某种能下载的东西，但其实这些API支持读、写和其他操作。
>
> - **客户端**是代表资源拥有者访问受保护资源的软件。如果你是Web开发人员，“客户端”这个名称会让你觉得它是指浏览器，但它在本书中并不是这个意思。如果你是商业应用开发人员，可能以为“客户端”是指付费使用服务的客户，3但这也不是它的正确含义。在OAuth中，只要软件使用了受保护资源上的API，它就是客户端。
>
>   ​                                                                                                                                                                   --《OAuth2.0实战》





### HTTP身份验证流程

参考资料：

[HTTP 身份验证](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Authentication)

HTTP提供了一套标准的身份验证框架：服务器可以用来针对客户端的请求发送质询(challenge)，客户端根据质询提供身份验证凭证。

质询与应答的工作流程如下：服务器端向客户端返回401（Unauthorized，未授权）状态码，并在WWW-Authenticate头中添加如何进行验证的信息，其中至少包含有一种质询方式。然后客户端可以在请求中添加Authorization头进行验证，其Value为身份验证的凭证信息。

![2799767-6d9e1014fd3bca72](images/identityserver4%E5%AE%9E%E6%88%98/2799767-6d9e1014fd3bca72.png)

其中：

**Authorization** 参见：https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Authorization

示例：

```html
Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l
```



#### Bearer认证

**Bearer认证**（也叫做令牌认证）是一种HTTP认证方案，其中包含的安全令牌的叫做**Bearer Token**。

Bearer验证中的凭证称为`BEARER_TOKEN`，或者是`access_token`，它的颁发和验证完全由我们自己的应用程序来控制，而不依赖于系统和Web服务器，Bearer验证的标准请求方式如下：

```text
Authorization: Bearer [BEARER_TOKEN] 
```

使用Bearer验证有什么好处呢？

- CORS: cookies + CORS 并不能跨不同的域名。而Bearer验证在任何域名下都可以使用HTTP header头部来传输用户信息。
- 对移动端友好: 当你在一个原生平台(iOS, Android, WindowsPhone等)时，使用Cookie验证并不是一个好主意，因为你得和Cookie容器打交道，而使用Bearer验证则简单的多。
- CSRF: 因为Bearer验证不再依赖于cookies, 也就避免了跨站请求攻击。
- 标准：在Cookie认证中，用户未登录时，返回一个`302`到登录页面，这在非浏览器情况下很难处理，而Bearer验证则返回的是标准的`401 challenge`。



Bearer认证的核心是Token。那如何确保**Token的安全**是重中之重。一种方式是使用Https，另一种方式就是对Token进行**加密签名**。而**JWT**就是一种比较流行的**Token编码方式**。

#### JWT

https://jwt.io/introduction/

https://tools.ietf.org/html/rfc7519



**JWT**就是一种比较流行的**Token编码方式**。

> Json web token (JWT), 是为了在网络应用环境间传递声明而执行的一种基于JSON的开放标准（[RFC 7519](https://tools.ietf.org/html/rfc7519)）,
>
> JWT的声明一般被用来在身份提供者和服务提供者间传递被认证的用户身份信息，以便于从资源服务器获取资源，也可以增加一些额外的其它业务逻辑所必须的声明信息，该token也可直接被用于认证，也可被加密。



JWT有三部分组成：
`<header>.<payload>.<signature>`

```md
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```

1. Header：由`alg`和`typ`组成，`alg`是algorithm(算法)的缩写，`typ`是type的缩写，指定token的类型。该部分使用`Base64Url`编码。

2. Payload：主要用来存储信息，包含各种声明，同样该部分也由`BaseURL`编码。

   这一部分是JWT主要的信息存储部分，其中包含了许多种的声明（claims）。

   Claims的实体一般包含用户和一些元数据，这些claims分成三种类型：

   - **reserved claims**：预定义的 一些声明，并不是强制的但是推荐，它们包括 iss (issuer), exp (expiration time), sub (subject),aud(audience) 等（这里都使用三个字母的原因是保证 JWT 的紧凑）。
   - **public claims**: 公有声明，这个部分可以随便定义，但是要注意和 IANA JSON Web Token 冲突。
   - **private claims**: 私有声明，这个部分是共享被认定信息中自定义部分。

3. Signature：签名，使用服务器端的密钥进行签名。以确保Token未被篡改。



使用JWT具有如下好处：

- **通用**：因为json的通用性，所以JWT是可以进行跨语言支持的，像JAVA,JavaScript,NodeJS,PHP等很多语言都可以使用。
- **紧凑**：JWT的构成非常简单，字节占用很小，可以通过 GET、POST 等放在 HTTP 的 header 中，非常便于传输。
- **扩展**：JWT是自我包涵的，包含了必要的所有信息，不需要在服务端保存会话信息, 非常易于应用的扩展。



#### JwtBearer认证

ASP.NET Core 认证与授权：JwtBearer认证

[ASP.NET Core Web Api之JWT(一)](https://www.cnblogs.com/CreateMyself/p/11123023.html)

[ASP.NET Core 认证与授权(4) : JwtBearer认证](https://www.cnblogs.com/RainingNight/p/jwtbearer-authentication-in-asp-net-core.html#%E6%B3%A8%E5%86%8Cjwtbearer%E8%AE%A4%E8%AF%81)



### OAuth2.0 授权模式

参考资料：

[OAuth 2.0, OpenID Connect & IdentityServer](https://chsakell.com/2019/03/11/asp-net-core-identity-series-oauth-2-0-openid-connect-identityserver/)



OAuth2.0 定义了四种授权模式：

2. Client Credentials：客户端凭证模式；该方法通常用于服务器之间的通讯；该模式仅发生在Client与Identity Server之间。
3. Resource Owner Password Credentials：用户密码模式
4. Authorization Code：授权码模式；
4. Implicit：隐式模式；直接通过浏览器的链接跳转申请令牌。隐式是相对于授权码模式而言的。其不再需要【Client】的参与，所有的认证和授权都是通过浏览器来完成的。



#### Client Credentials

![2799767-b8f1275cda8b204d](images/identityserver4%E5%AE%9E%E6%88%98/2799767-b8f1275cda8b204d.png)



客户端凭证模式，是最简单的授权模式，因为授权的流程仅发生在Client与Identity Server之间。

该模式的适用场景为服务器与服务器之间的通信



#### Resource Owner Password Credentials

![2799767-934f091397d7234b](images/identityserver4%E5%AE%9E%E6%88%98/2799767-934f091397d7234b-1605236684043.png)

Resource Owner其实就是User，所以可以直译为用户名密码模式。密码模式相较于客户端凭证模式，多了一个参与者，就是User。通过User的用户名和密码向Identity Server申请访问令牌。这种模式下要求客户端不得储存密码。但我们并不能确保客户端是否储存了密码，所以该模式仅适用于受信任的客户端。否则会发生密码泄露的危险。**该模式不推荐使用**。



#### Authorization Code

![2799767-15e218058b896231](images/identityserver4%E5%AE%9E%E6%88%98/2799767-15e218058b896231.png)

授权码模式是一种混合模式，是目前功能最完整、流程最严密的授权模式。它主要分为两大步骤：认证和授权。
其流程为：

1. 用户访问客户端，客户端将用户导向Identity Server。
2. 用户填写凭证信息向客户端授权，认证服务器根据客户端指定的重定向URI，并返回一个【Authorization Code】给客户端。
3. 客户端根据【Authorization Code】向Identity Server申请【Access Token】



#### Implicit

![2799767-890a555d2a3922d3](images/identityserver4%E5%AE%9E%E6%88%98/2799767-890a555d2a3922d3.png)

隐式是相对于授权码模式而言的。其不再需要【Client】的参与，所有的认证和授权都是通过浏览器来完成的。



## IdentityServer4 集成

[官网](https://www.identityserver.io/)

[英文文档](https://identityserver4.readthedocs.io/en/latest/)

[中文文档](http://www.identityserver.com.cn/)





![2799767-6708925e096c8510](images/identityserver4%E5%AE%9E%E6%88%98/2799767-6708925e096c8510-1605238475553.png)



IdentityServer4是为ASP.NET CORE量身定制的实现了OpenId Connect和OAuth2.0协议的认证授权中间件。
下面就来介绍如何集成IdentityServer4。其主要分为三步：

1. IdentityServer如何配置和启用IdentityServer中间件
2. Resources如何配置和启用认证授权中间件
3. Client如何认证和授权

### Identity Server 中间件的配置和启用

作为一个独立的Identity Server，它必须知道哪些资源需要保护，必须知道哪些客户端能够允许访问，这是配置的基础。
所以IdentityServer中间件的配置的核心就是：

1. 配置受保护的资源列表
2. 配置允许验证的Client





## 实战

[实战视频教程](https://www.bilibili.com/video/BV16b411k7yM?p=4)

### Client Credentials（客户端凭证模式）

该方法不需要用户参与，通常用于服务器之间的通讯；该模式仅发生在Client与Identity Server之间。

示例代码：[**1_ClientCredentials**](https://github.com/IdentityServer/IdentityServer4/tree/main/samples/Quickstarts/1_ClientCredentials)

对应文档：[1_client_credentials](https://identityserver4.readthedocs.io/en/latest/quickstarts/1_client_credentials.html)

跟着官方文档做，

新建三个项目：

1. IdentityServer：认证服务
2. Api：为提供`Client`提供Api
3. Client：使用项目`Api`的Api

#### IdentityServer：认证服务

1. 新建一个web应用程序,添加`IdentityServer4`包

   启动端口修改为https:https://localhost:5001

   

2. 添加类`Config.cs`

   ```c#
   using IdentityServer4.Models;
   using System.Collections.Generic;
   
   namespace IdentityServer
   {
       public static class Config
       {
           public static IEnumerable<IdentityResource> IdentityResources =>
               new IdentityResource[]
               {
                   new IdentityResources.OpenId()
               };
   
           public static IEnumerable<ApiScope> ApiScopes =>
               new List<ApiScope>
               {
                   new ApiScope("api1", "My API")
               };
   
           public static IEnumerable<Client> Clients =>
               new List<Client>
               {
                   new Client
                   {
                       ClientId = "client",
   
                       // no interactive user, use the clientid/secret for authentication
                       // 没有交互性用户，使用 clientid/secret 实现认证。
                       AllowedGrantTypes = GrantTypes.ClientCredentials,
   
                       // secret for authentication
                       // 用于认证的密码
                       ClientSecrets =
                       {
                           new Secret("secret".Sha256())
                       },
   
                       // scopes that client has access to
                       // 客户端有权访问的范围（Scopes）
                       AllowedScopes = { "api1" }
                   }
               };
       }
   }
   ```

   

3. 添加`IdentityServer`服务及其中间件

   - `ConfigureServices`方法添加

     ```c#
             public void ConfigureServices(IServiceCollection services)
             {
                 ......
                 var builder = services.AddIdentityServer(options =>
                 {
                     // see https://identityserver4.readthedocs.io/en/latest/topics/resources.html
                     options.EmitStaticAudienceClaim = true;
                 })
                     .AddInMemoryIdentityResources(Config.IdentityResources)
                     .AddInMemoryApiScopes(Config.ApiScopes)
                     .AddInMemoryClients(Config.Clients);
     
                 // not recommended for production - you need to store your key material somewhere secure
                 //不推荐用于生产-您需要将关键材料存储在安全的地方
                 builder.AddDeveloperSigningCredential();
                  ......
             }
     ```

   - `Configure`方法添加

     ```c#
             public void Configure(IApplicationBuilder app)
             {
                 ......
                 app.UseIdentityServer();
                 ......
             }
     ```

 运行项目后，访问如下地址：

https://localhost:5001/.well-known/openid-configuration

可以查看到IdentityServer的各种元数据信息

```json
{
  "issuer": "https://localhost:5001",
  "jwks_uri": "https://localhost:5001/.well-known/openid-configuration/jwks",
  "authorization_endpoint": "https://localhost:5001/connect/authorize",
  "token_endpoint": "https://localhost:5001/connect/token",
  "userinfo_endpoint": "https://localhost:5001/connect/userinfo",
  "end_session_endpoint": "https://localhost:5001/connect/endsession",
  "check_session_iframe": "https://localhost:5001/connect/checksession",
  "revocation_endpoint": "https://localhost:5001/connect/revocation",
  "introspection_endpoint": "https://localhost:5001/connect/introspect",
  "device_authorization_endpoint": "https://localhost:5001/connect/deviceauthorization",
  "frontchannel_logout_supported": true,
  "frontchannel_logout_session_supported": true,
  "backchannel_logout_supported": true,
  "backchannel_logout_session_supported": true,
  "scopes_supported": [
    "openid",
    "api1",
    "offline_access"
  ],
  "claims_supported": [
    "sub"
  ],
  "grant_types_supported": [
    "authorization_code",
    "client_credentials",
    "refresh_token",
    "implicit",
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



#### Api

   这作为我们要保护起来的资源

1. 创建一个webApi项目，确保添加`Microsoft.AspNetCore.Authentication.JwtBearer`包，aspnet.core3.1默认已经添加

2. 修改https端口为6001，在 `launchSettings.json`中修改为：

   ```json
   {
     "$schema": "http://json.schemastore.org/launchsettings.json",
     "iisSettings": {
         ......
         "applicationUrl": "http://localhost:6000",
         "sslPort": 6001
       }
     },
     "profiles": {
       "IIS Express": {
       },
       "Api": {
         "applicationUrl": "https://localhost:6001;http://localhost:6000",
          ......
         }
       }
     }
   }
   ```

   

3. 添加控制器`IdentityController`

   ```c#
       [Route("identity")]
       [Authorize]
       public class IdentityController : ControllerBase
       {
           [HttpGet]
           public IActionResult Get()
           {
               return new JsonResult(from c in User.Claims select new { c.Type, c.Value });
           }
       }
   ```

   ​	这是我们要暴露给Client使用的Api

   

4. 添加`AddAuthentication`服务

   ```c#
           public void ConfigureServices(IServiceCollection services)
           {
               ......
               services.AddAuthentication("Bearer")
                       .AddJwtBearer("Bearer", options =>
                       {
                           options.Authority = "https://localhost:5001";
   
                           options.TokenValidationParameters = new TokenValidationParameters
                           {
                               ValidateAudience = false
                           };
                       });
           }
   ```

   

5. 启用认证和授权中间件

   ```c#
           public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
           {
               ......
               app.UseAuthentication();
               app.UseAuthorization();
               ......
           }
   ```

   这时，访问http://localhost:6001/identity，返回401

   

#### Client

#####   控制台程序

   使用控制台程序作为Client端进行验证：

1. 添加一个控制台程序，添加包`IdentityModel`的依赖

2. 修改`main.cs`

   ```c#
   using IdentityModel.Client;
   using Newtonsoft.Json.Linq;
   using System;
   using System.Net.Http;
   using System.Threading.Tasks;
   
   namespace Client
   {
       class Program
       {
           static async Task Main(string[] args)
           {
               // discover endpoints from metadata
               // 获取端点元数据
               var client = new HttpClient();
               var disco = await client.GetDiscoveryDocumentAsync("https://localhost:5001");
               if (disco.IsError)
               {
                   Console.WriteLine(disco.Error);
                   return;
               }
   
               // request token
               // 请求获取token
               var tokenResponse = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
               {
                   Address = disco.TokenEndpoint, ///Access Token URL：https://localhost:5001/connect/token
   
                   ClientId = "client",
                   ClientSecret = "secret",
                   Scope = "api1"
               });
   
               if (tokenResponse.IsError)
               {
                   Console.WriteLine(tokenResponse.Error);
                   return;
               }
   
               Console.WriteLine(tokenResponse.Json);
               Console.WriteLine("\n\n");
   
               // call api
               var apiClient = new HttpClient();
               //使用AccessToken访问Api
               apiClient.SetBearerToken(tokenResponse.AccessToken);
   
               var response = await apiClient.GetAsync("https://localhost:6001/identity");
               if (!response.IsSuccessStatusCode)
               {
                   Console.WriteLine(response.StatusCode);
               }
               else
               {
                   var content = await response.Content.ReadAsStringAsync();
                   Console.WriteLine(JArray.Parse(content));
               }
   
               Console.ReadKey();
           }
       }
   }
   
   
   ```


输出：

IdentiyServer服务器返回：
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjlDMkZDQjVGQTcxMDkzQjQ3RkJDNDZGMEU2NzIxMkVEIiwidHlwIjoiYXQrand0In0.eyJuYmYiOjE2MDUyNzQ1NjUsImV4cCI6MTYwNTI3ODE2NSwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTAwMSIsImF1ZCI6Imh0dHBzOi8vbG9jYWxob3N0OjUwMDEvcmVzb3VyY2VzIiwiY2xpZW50X2lkIjoiY2xpZW50IiwianRpIjoiQTlERjA4MjhBRkJGRUY3NTQ3QTY1MzhGRUYwQkY2OUQiLCJpYXQiOjE2MDUyNzQ1NjUsInNjb3BlIjpbImFwaTEiXX0.MA6TNdEO8KsRGsu5fuYqvfE4n-ZeCyPL_ByKQkoh_f4vw7ljUIPswx2n3KKzEm5HmnL8xt6TaLABBBOSlzxXSk39vgJ-3hQK_kTMBTqZx-IX7xkogRlB28fI3nQnQAKlGKT-cMnSoTl0iR95exjPwtOkqzN0eFT4WmPOb2zmY7K8DbacMhMHIHTSS3cmnJZJ6QrdIoLI6eqRKPrXr83JMUvBn5Q6yio9FZX1ZaPmRWa9amp_BlilxtkxN8XLEMko4BfySiceY0DCuXEtQ-qfK1zBm9LOoqZxhJk9xFgWAmlYM8BJwnqyj1zGPmNKwbGC2TiE968HWhN4XrpfL6_aFA",
  "expires_in": 3600,
  "token_type": "Bearer",
  "scope": "api1"
}
```

访问Api服务器https://localhost:6001/identity  ，返回：
```json
[
    {
        "type": "nbf",
        "value": "1605274410"
    },
    {
        "type": "exp",
        "value": "1605278010"
    },
    {
        "type": "iss",
        "value": "https://localhost:5001"
    },
    {
        "type": "aud",
        "value": "https://localhost:5001/resources"
    },
    {
        "type": "client_id",
        "value": "client"
    },
    {
        "type": "jti",
        "value": "8EEB078ED3FC0A2B37105564B5FB5380"
    },
    {
        "type": "iat",
        "value": "1605274410"
    },
    {
        "type": "scope",
        "value": "api1"
    }
]
```

其中，返回的`access_token`:

```md
eyJhbGciOiJSUzI1NiIsImtpZCI6IjlDMkZDQjVGQTcxMDkzQjQ3RkJDNDZGMEU2NzIxMkVEIiwidHlwIjoiYXQrand0In0.eyJuYmYiOjE2MDUyNzQ1NjUsImV4cCI6MTYwNTI3ODE2NSwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTAwMSIsImF1ZCI6Imh0dHBzOi8vbG9jYWxob3N0OjUwMDEvcmVzb3VyY2VzIiwiY2xpZW50X2lkIjoiY2xpZW50IiwianRpIjoiQTlERjA4MjhBRkJGRUY3NTQ3QTY1MzhGRUYwQkY2OUQiLCJpYXQiOjE2MDUyNzQ1NjUsInNjb3BlIjpbImFwaTEiXX0.MA6TNdEO8KsRGsu5fuYqvfE4n-ZeCyPL_ByKQkoh_f4vw7ljUIPswx2n3KKzEm5HmnL8xt6TaLABBBOSlzxXSk39vgJ-3hQK_kTMBTqZx-IX7xkogRlB28fI3nQnQAKlGKT-cMnSoTl0iR95exjPwtOkqzN0eFT4WmPOb2zmY7K8DbacMhMHIHTSS3cmnJZJ6QrdIoLI6eqRKPrXr83JMUvBn5Q6yio9FZX1ZaPmRWa9amp_BlilxtkxN8XLEMko4BfySiceY0DCuXEtQ-qfK1zBm9LOoqZxhJk9xFgWAmlYM8BJwnqyj1zGPmNKwbGC2TiE968HWhN4XrpfL6_aFA
```

可通过[jwt.ms](https://jwt.ms/)或[jwt.io](https://jwt.io/)进行解析：

```json
{
  "alg": "RS256",
  "kid": "9C2FCB5FA71093B47FBC46F0E67212ED",
  "typ": "at+jwt"
}.{
  "nbf": 1605274565,
  "exp": 1605278165,
  "iss": "https://localhost:5001",
  "aud": "https://localhost:5001/resources",
  "client_id": "client",
  "jti": "A9DF0828AFBFEF7547A6538FEF0BF69D",
  "iat": 1605274565,
  "scope": [
    "api1"
  ]
}.[Signature]
```

关于jwt字段的解释，参看：https://tools.ietf.org/html/rfc7519#section-4



##### PostMan

使用PostMan作为Client端进行验证：

![image-20201113193253279](images/identityserver4%E5%AE%9E%E6%88%98/image-20201113193253279.png)

![image-20201113193535826](images/identityserver4%E5%AE%9E%E6%88%98/image-20201113193535826.png

![image-20201113193614301](images/identityserver4%E5%AE%9E%E6%88%98/image-20201113193614301.png)

![image-20201113193742030](images/identityserver4%E5%AE%9E%E6%88%98/image-20201113193742030.png)

![image-20201113194055608](images/identityserver4%E5%AE%9E%E6%88%98/image-20201113194055608.png)



### ResourceOwnerPassword（资源所有者密码模式）

OAuth 2.0 资源所有者密码模式允许客户端向令牌服务发送用户名和密码，并获取**代表该用户**的访问令牌。

示例及其文档：[IdentityServer4（8）- 使用密码认证方式控制API访问（资源所有者密码授权模式）](https://www.cnblogs.com/stulzq/p/7509648.html)

#### IdentityServer：认证服务

`TestUser` 类代表测试用户及其身份信息单元（Claim）

##### 添加几个用户

在`Confing.cs`文件中，

```C#
using IdentityServer4.Test;

public static List<TestUser> GetUsers()
{
    return new List<TestUser>
    {
        new TestUser
        {
            SubjectId = "SubjectId-1",
            Username = "alice",
            Password = "password"
        },
        new TestUser
        {
            SubjectId = "SubjectId-2",
            Username = "bob",
            Password = "password"
        }
    };
}
```



##### 将测试用户注册到 IdentityServer

`Startup.cs`

```c#
public void ConfigureServices(IServiceCollection services)
{
    // uncomment, if you want to add an MVC-based UI
    //services.AddControllersWithViews();

    var builder = services.AddIdentityServer(options =>{
           // see https://identityserver4.readthedocs.io/en/latest/topics/resources.html
            options.EmitStaticAudienceClaim = true; })
        .AddInMemoryIdentityResources(Config.IdentityResources)
        .AddInMemoryApiScopes(Config.ApiScopes)
        .AddInMemoryClients(Config.Clients)
        .AddTestUsers(Config.GetUsers());
```

##### 为资源所有者密码授权添加一个客户端定义

`Config.cs`

```C#
public static IEnumerable<Client> GetClients()
{
    return new List<Client>
    {
        // other clients omitted...

        // resource owner password grant client
        new Client
        {
            ClientId = "ro.client",
            AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,

            ClientSecrets =
            {
                new Secret("secret".Sha256())
            },
            AllowedScopes = { "api1" }
        }
    };
}
```

#### Api

与Client Credentials（客户端凭证模式）的Api项目一样，未做修改

#### Client

##### 控制台程序

`main.cs`

```c#
using IdentityModel.Client;
using Newtonsoft.Json.Linq;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace Client
{
    class Program
    {
        static async Task Main(string[] args)
        {
            // discover endpoints from metadata
            // 获取端点元数据
            var client = new HttpClient();
            var disco = await client.GetDiscoveryDocumentAsync("https://localhost:5001");
            if (disco.IsError)
            {
                Console.WriteLine(disco.Error);
                return;
            }

            // request token
            // 请求获取token
            var tokenResponse = await client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = disco.TokenEndpoint, //Access Token URL：https://localhost:5001/connect/token

                ClientId = "ro.client",
                ClientSecret = "secret",

                UserName="alice",
                Password="password",

                Scope = "api1"
            });

            if (tokenResponse.IsError)
            {
                Console.WriteLine(tokenResponse.Error);
                return;
            }

            Console.WriteLine(tokenResponse.Json);
            Console.WriteLine("\n\n");

            // call api
            var apiClient = new HttpClient();
            //使用AccessToken访问Api
            apiClient.SetBearerToken(tokenResponse.AccessToken);

            var response = await apiClient.GetAsync("https://localhost:6001/identity");
            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine(response.StatusCode);
            }
            else
            {
                var content = await response.Content.ReadAsStringAsync();
                Console.WriteLine(JArray.Parse(content));
            }

            Console.ReadKey();
        }
    }
}

```

请求`access_token`代码：

```c#
            var tokenResponse = await client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = disco.TokenEndpoint, //Access Token URL：https://localhost:5001/connect/token

                ClientId = "ro.client",
                ClientSecret = "secret",

                UserName="alice",
                Password="password",

                Scope = "api1"
            });
```

调用Api返回

```json
[
    {
        "type": "nbf",
        "value": "1605331158"
    },
    {
        "type": "exp",
        "value": "1605334758"
    },
    {
        "type": "iss",
        "value": "https://localhost:5001"
    },
    {
        "type": "aud",
        "value": "https://localhost:5001/resources"
    },
    {
        "type": "client_id",
        "value": "ro.client"
    },
    {
        "type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
        "value": "SubjectId-1"
    },
    {
        "type": "auth_time",
        "value": "1605331158"
    },
    {
        "type": "http://schemas.microsoft.com/identity/claims/identityprovider",
        "value": "local"
    },
    {
        "type": "jti",
        "value": "1AC073BFBE63AD2C8F0C2891F9EA67AA"
    },
    {
        "type": "iat",
        "value": "1605331158"
    },
    {
        "type": "scope",
        "value": "api1"
    },
    {
        "type": "http://schemas.microsoft.com/claims/authnmethodsreferences",
        "value": "pwd"
    }
]
```



返回的`access_token`:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjlDMkZDQjVGQTcxMDkzQjQ3RkJDNDZGMEU2NzIxMkVEIiwidHlwIjoiYXQrand0In0.eyJuYmYiOjE2MDUzMzIwNTUsImV4cCI6MTYwNTMzNTY1NSwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTAwMSIsImF1ZCI6Imh0dHBzOi8vbG9jYWxob3N0OjUwMDEvcmVzb3VyY2VzIiwiY2xpZW50X2lkIjoicm8uY2xpZW50Iiwic3ViIjoiU3ViamVjdElkLTEiLCJhdXRoX3RpbWUiOjE2MDUzMzIwNTUsImlkcCI6ImxvY2FsIiwianRpIjoiQTdDRDNDQUNBMUE1MzJEMEUwQkU2RURCRDVENkQ2MzYiLCJpYXQiOjE2MDUzMzIwNTUsInNjb3BlIjpbImFwaTEiXSwiYW1yIjpbInB3ZCJdfQ.Sg3-tp7lFHN6jSGMMpNgZSEmTQY6wxV49i9WbKWlaWvnslJH1L8mQ_6vZSXuSZosJs5bmEkQzOFTg38WdxYcBtjKsTsxAVlEeshWhCcU0GEeha-GU3ZmQ7xD7bAkudvOxqV2GDzbodvEE4uwep1-bjpNexrepe4D-Bddxs2z_WUl412rFeL9wRkxBa9XgWrf1AZFsysy-fR7ALon1VZeHMOfVLAum7p1VpLl1rsSwUzV9xaGN-v2G_GehtRIyBuYPSTDEaHm5XrCUcPJzDGgPQ-fkDqK387CUuyevbzd_sO_0NHsvRwpLgE4qtKATmTd-_wicxMGRZVZ_9Z67rA_UQ",
  "expires_in": 3600,
  "token_type": "Bearer",
  "scope": "api1"
}

```

**ResourceOwnerPassword**返回的`access_token`:

```json
{
  "alg": "RS256",
  "kid": "9C2FCB5FA71093B47FBC46F0E67212ED",
  "typ": "at+jwt"
}.{
  "nbf": 1605332055,
  "exp": 1605335655,
  "iss": "https://localhost:5001",
  "aud": "https://localhost:5001/resources",
  "client_id": "ro.client",
  "sub": "SubjectId-1",
  "auth_time": 1605332055,
  "idp": "local",
  "jti": "A7CD3CACA1A532D0E0BE6EDBD5D6D636",
  "iat": 1605332055,
  "scope": [
    "api1"
  ],
  "amr": [
    "pwd"
  ]
}.[Signature]
```

**Client Credentials**返回的`access_token`:

```json
{
  "alg": "RS256",
  "kid": "9C2FCB5FA71093B47FBC46F0E67212ED",
  "typ": "at+jwt"
}.{
  "nbf": 1605274565,
  "exp": 1605278165,
  "iss": "https://localhost:5001",
  "aud": "https://localhost:5001/resources",
  "client_id": "client",
  "jti": "A9DF0828AFBFEF7547A6538FEF0BF69D",
  "iat": 1605274565,
  "scope": [
    "api1"
  ]
}.[Signature]
```

相比，多了一个包含唯一标识用户的`sub` claim

```json
 "sub": "SubjectId-1",
```

该信息是用户的唯一标识。sub 信息可以在调用 API 后通过检查内容变量来被查看，并且也将被控制台应用程序显示到屏幕上,如下所示：

```json
[
    .......
    {
        "type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
        "value": "SubjectId-1"
    },
   ......
]
```

sub 信息的存在（或缺失）**使得 API 能够区分代表客户端的调用和代表用户的调用**。



The "sub" (subject) claim identifies the principal that is the subject of the JWT. The claims in a JWT are normally statements about the subject. The subject value MUST either be scoped to be locally unique in the context of the issuer or be globally unique. The processing of this claim is generally application specific. The "sub" value is a case-sensitive string containing a StringOrURI value. [[RFC 7519](https://tools.ietf.org/html/rfc7519), [Section 4.1.2](https://tools.ietf.org/html/rfc7519#section-4.1.2)]

```json
amr	pwd
```

Authentication Methods References. JSON array of strings that are identifiers for authentication methods used in the authentication. For instance, values might indicate that both password and OTP authentication methods were used. The definition of particular values to be used in the "amr" Claim is beyond the scope of this specification. Parties using this claim will need to agree upon the meanings of the values used, which may be context-specific. The "amr" value is an array of case sensitive strings. [[RFC 8176](https://tools.ietf.org/html/rfc8176), [Section 1](https://tools.ietf.org/html/rfc8176#section-1), reference values: [Section 2](https://tools.ietf.org/html/rfc8176#section-2)]



##### PostMan

![image-20201114132112116](images/identityserver4%E5%AE%9E%E6%88%98/image-20201114132112116.png)

![image-20201114132223693](images/identityserver4%E5%AE%9E%E6%88%98/image-20201114132223693.png)



### 基于 OpenID Connect 的用户认证

参考资料：

[基于 OpenID Connect 的用户认证](http://www.identityserver.com.cn/Home/Detail/openidConnect)

[IdentityServer4（9）- 使用OpenID Connect添加用户身份验证（implicit)](https://www.cnblogs.com/stulzq/p/7797341.html)

[OAuth 2.0, OpenID Connect & IdentityServer](https://chsakell.com/2019/03/11/asp-net-core-identity-series-oauth-2-0-openid-connect-identityserver/)

> 在描述OAuth 2.0时，我们说过它的目的是发布访问令牌，以提供对受保护资源的有限**访问权限**，换句话说，OAuth 2.0提供**授权，**但不提供身份验证。实际用户永远不会直接与客户端应用程序本身进行身份验证。访问令牌提供了一个`pseudo-authentication`完全没有身份隐含的级别。伪身份验证不提供有关身份验证的时间，地点或方式的信息。在此`OpenID Connect`输入并填补OAuth 2.0中的身份验证空白或限制。
> `OpenID Connect`是OAuth 2.0协议之上的简单身份层。它使客户端可以根据授权服务器执行的身份验证来验证最终用户的身份。它以可互操作且类似于REST的方式*（引入新的REST端点）*获取有关最终​​用户的基本配置文件信息。它使用**Claims**传达有关最终用户的信息，并以基于云的应用程序可以以下方式扩展OAuth：
>
> - 获取身份信息
> - 检索有关身份验证事件的详细信息
> - 允许联合单点登录
>
> 让我们看看OpenID Connect中使用的基本术语。
>
> 1. **最终用户**：人类参与者–在OAuth中，它是指拥有资源作为其受保护资源之一的资源所有者
> 2. **依赖方**：OAuth 2.0客户端应用程序。需要最终用户身份验证和来自OpenID提供程序的声明
> 3. **身份提供者**：OAuth 2.0授权服务器，用于对最终用户进行身份验证，并向依赖方提供有关身份验证事件和最终用户的声明
> 4. **身份令牌**：**JSON Web令牌（JWT），**其中包含有关身份验证事件的声明。它还可能包含其他声明



 由于OpenID Connect位于OAuth 2.0之上，因此，如果我们说它使用了某些OAuth 2.0流程，就很有意义。实际上，OpenID Connect可以遵循以下`Authorization Code`流程，“`Implicit`和”`Hybrid`（前两个的组合）。流程完全相同，唯一的区别是**id_token**与**access_token**一起发出。**该流是纯OAuth 2.0还是OpenID Connect，取决于授权请求中的openid范围是否存在。** 