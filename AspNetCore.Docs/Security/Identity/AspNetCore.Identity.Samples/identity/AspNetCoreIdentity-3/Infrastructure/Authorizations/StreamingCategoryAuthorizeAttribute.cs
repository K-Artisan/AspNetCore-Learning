using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace AspNetCoreIdentity.Infrastructure.Authorizations
{
    /// <summary>
    /// 这里的问题是，您将如何对每个类别实施授权？当然，您可以为每个授权创建基于声明的授权，
    /// 或者甚至可以为每个类别和相关的基于角色的策略创建特定的角色。
    /// 
    /// 但是，有一种更好，更清洁的方法可以完成此任务，这就是定制授权策略提供程序出现的地方
    /// 
    /// 我们将属性的Category属性设置为StreamingCategory.ACTION_AND_ADVENTURE，这意味着：
    /// Policy = "StreamingCategory_ACTION_AND_ADVENTURE";
    /// 
    /// 定义`StreamingCategoryAuthorizeAttribute : AuthorizeAttribute`相当于只是定义了策略名
    /// 
    /// 下一步还需要为这个策略定义策略提供者
    /// StreamingCategoryPolicyProvider : IAuthorizationPolicyProvider
    /// 其中，IAuthorizationPolicyProvider接口方法
    /// StreamingCategoryPolicyProvider.GetPolicyAsync(string policyName)会根据策略的名称创建一个Policy，
    /// 并且往Policy添加一个要求（Requirement， 必须继承空接口IAuthorizationRequirement），
    /// policy.AddRequirements(new StreamingCategoryRequirement(category.ToString()));
    ///
    /// 至此，策略名，策略，策略的具体要求 都有了，还缺一个处理程序来判断是否满足这个策略（具体落实判断是否满足策略中的Requirement，Claim等），即：
    /// StreamingCategoryAuthorizationHandler : AuthorizationHandler<StreamingCategoryRequirement>
    /// 
    /// </summary>
    public class StreamingCategoryAuthorizeAttribute : AuthorizeAttribute
    {
        const string POLICY_PREFIX = "StreamingCategory_";
        public StreamingCategoryAuthorizeAttribute(StreamingCategory category) => Category = category;

        public StreamingCategory Category
        {
            get
            {
                var category = Enum.Parse(typeof(StreamingCategory), POLICY_PREFIX.Substring(POLICY_PREFIX.Length));
                return (StreamingCategory)category;
            }

            set
            {
                Policy = $"{POLICY_PREFIX}{value.ToString()}";
            }
        }
    }
}
