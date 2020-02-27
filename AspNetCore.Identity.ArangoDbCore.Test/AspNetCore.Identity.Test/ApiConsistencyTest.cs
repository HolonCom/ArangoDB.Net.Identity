using System.Reflection;
using AspNetCore.Identity.ArangoDbCore.Test.Shared;
using Microsoft.AspNetCore.Identity;

namespace AspNetCore.Identity.ArangoDbCore.Test.AspNetCore.Identity.Test
{
    public class ApiConsistencyTest: ApiConsistencyTestBase
    {
        protected override Assembly TargetAssembly => typeof(IdentityOptions).GetTypeInfo().Assembly;

    }
}
