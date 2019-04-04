#pragma checksum "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "e5dbbd2b77e0205ff57d1bf1f99f947f0ebba4dd"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Grants_Index), @"mvc.1.0.view", @"/Views/Grants/Index.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Grants/Index.cshtml", typeof(AspNetCore.Views_Grants_Index))]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#line 1 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
using IdentityServer.ViewModels;

#line default
#line hidden
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"e5dbbd2b77e0205ff57d1bf1f99f947f0ebba4dd", @"/Views/Grants/Index.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"dd26766d6e7f26590b5e3d63380121bcf6a0e143", @"/Views/_ViewImports.cshtml")]
    public class Views_Grants_Index : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<GrantsViewModel>
    {
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_0 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("asp-action", "Revoke", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        #line hidden
        #pragma warning disable 0169
        private string __tagHelperStringValueBuffer;
        #pragma warning restore 0169
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperExecutionContext __tagHelperExecutionContext;
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner __tagHelperRunner = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner();
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __backed__tagHelperScopeManager = null;
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __tagHelperScopeManager
        {
            get
            {
                if (__backed__tagHelperScopeManager == null)
                {
                    __backed__tagHelperScopeManager = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager(StartTagHelperWritingScope, EndTagHelperWritingScope);
                }
                return __backed__tagHelperScopeManager;
            }
        }
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper;
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.RenderAtEndOfFormTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper;
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(58, 333, true);
            WriteLiteral(@"<div class=""grants"">
    <div class=""row page-header"">
        <div class=""col-sm-10"">
            <h1>
                Client Application Access
            </h1>
            <div>Below is the list of applications you have given access to and the names of the resources they have access to.</div>
        </div>
    </div>
");
            EndContext();
#line 12 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
     if (Model.Grants.Any() == false)
    {

#line default
#line hidden
            BeginContext(437, 238, true);
            WriteLiteral("        <div class=\"row\">\r\n            <div class=\"col-sm-8\">\r\n                <div class=\"alert alert-info\">\r\n                    You have not given access to any applications\r\n                </div>\r\n            </div>\r\n        </div>\r\n");
            EndContext();
#line 21 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
    }
    else
    {
        foreach (var grant in Model.Grants)
        {

#line default
#line hidden
            BeginContext(755, 77, true);
            WriteLiteral("            <div class=\"row grant\">\r\n                <div class=\"col-sm-2\">\r\n");
            EndContext();
#line 28 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
                     if (grant.ClientLogoUrl != null)
                    {

#line default
#line hidden
            BeginContext(910, 28, true);
            WriteLiteral("                        <img");
            EndContext();
            BeginWriteAttribute("src", " src=\"", 938, "\"", 964, 1);
#line 30 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
WriteAttributeValue("", 944, grant.ClientLogoUrl, 944, 20, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(965, 3, true);
            WriteLiteral(">\r\n");
            EndContext();
#line 31 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
                    }

#line default
#line hidden
            BeginContext(991, 108, true);
            WriteLiteral("                </div>\r\n                <div class=\"col-sm-8\">\r\n                    <div class=\"clientname\">");
            EndContext();
            BeginContext(1100, 16, false);
#line 34 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
                                       Write(grant.ClientName);

#line default
#line hidden
            EndContext();
            BeginContext(1116, 97, true);
            WriteLiteral("</div>\r\n                    <div>\r\n                        <span class=\"created\">Created:</span> ");
            EndContext();
            BeginContext(1214, 36, false);
#line 36 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
                                                         Write(grant.Created.ToString("yyyy-MM-dd"));

#line default
#line hidden
            EndContext();
            BeginContext(1250, 30, true);
            WriteLiteral("\r\n                    </div>\r\n");
            EndContext();
#line 38 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
                     if (grant.Expires.HasValue)
                    {

#line default
#line hidden
            BeginContext(1353, 97, true);
            WriteLiteral("                        <div>\r\n                            <span class=\"expires\">Expires:</span> ");
            EndContext();
            BeginContext(1451, 42, false);
#line 41 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
                                                             Write(grant.Expires.Value.ToString("yyyy-MM-dd"));

#line default
#line hidden
            EndContext();
            BeginContext(1493, 34, true);
            WriteLiteral("\r\n                        </div>\r\n");
            EndContext();
#line 43 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
                    }

#line default
#line hidden
            BeginContext(1550, 20, true);
            WriteLiteral("                    ");
            EndContext();
#line 44 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
                     if (grant.IdentityGrantNames.Any())
                    {

#line default
#line hidden
            BeginContext(1631, 139, true);
            WriteLiteral("                        <div>\r\n                            <div class=\"granttype\">Identity Grants</div>\r\n                            <ul>\r\n");
            EndContext();
#line 49 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
                                 foreach (var name in grant.IdentityGrantNames)
                                {

#line default
#line hidden
            BeginContext(1886, 40, true);
            WriteLiteral("                                    <li>");
            EndContext();
            BeginContext(1927, 4, false);
#line 51 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
                                   Write(name);

#line default
#line hidden
            EndContext();
            BeginContext(1931, 7, true);
            WriteLiteral("</li>\r\n");
            EndContext();
#line 52 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
                                }

#line default
#line hidden
            BeginContext(1973, 67, true);
            WriteLiteral("                            </ul>\r\n                        </div>\r\n");
            EndContext();
#line 55 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
                    }

#line default
#line hidden
            BeginContext(2063, 20, true);
            WriteLiteral("                    ");
            EndContext();
#line 56 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
                     if (grant.ApiGrantNames.Any())
                    {

#line default
#line hidden
            BeginContext(2139, 134, true);
            WriteLiteral("                        <div>\r\n                            <div class=\"granttype\">API Grants</div>\r\n                            <ul>\r\n");
            EndContext();
#line 61 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
                                 foreach (var name in grant.ApiGrantNames)
                                {

#line default
#line hidden
            BeginContext(2384, 40, true);
            WriteLiteral("                                    <li>");
            EndContext();
            BeginContext(2425, 4, false);
#line 63 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
                                   Write(name);

#line default
#line hidden
            EndContext();
            BeginContext(2429, 7, true);
            WriteLiteral("</li>\r\n");
            EndContext();
#line 64 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
                                }

#line default
#line hidden
            BeginContext(2471, 67, true);
            WriteLiteral("                            </ul>\r\n                        </div>\r\n");
            EndContext();
#line 67 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
                    }

#line default
#line hidden
            BeginContext(2561, 84, true);
            WriteLiteral("                </div>\r\n                <div class=\"col-sm-2\">\r\n                    ");
            EndContext();
            BeginContext(2645, 221, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("form", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "55ca4cbf9f674fe2aa7ac264a1633e1d", async() => {
                BeginContext(2671, 62, true);
                WriteLiteral("\r\n                        <input type=\"hidden\" name=\"clientId\"");
                EndContext();
                BeginWriteAttribute("value", " value=\"", 2733, "\"", 2756, 1);
#line 71 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
WriteAttributeValue("", 2741, grant.ClientId, 2741, 15, false);

#line default
#line hidden
                EndWriteAttribute();
                BeginContext(2757, 102, true);
                WriteLiteral(">\r\n                        <button class=\"btn btn-danger\">Revoke Access</button>\r\n                    ");
                EndContext();
            }
            );
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.RenderAtEndOfFormTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.Action = (string)__tagHelperAttribute_0.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_0);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(2866, 46, true);
            WriteLiteral("\r\n                </div>\r\n            </div>\r\n");
            EndContext();
#line 76 "C:\Users\bede.fulop\source\repos\ISTest\IdentityServer\Views\Grants\Index.cshtml"
        }
    }

#line default
#line hidden
            BeginContext(2930, 6, true);
            WriteLiteral("</div>");
            EndContext();
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<GrantsViewModel> Html { get; private set; }
    }
}
#pragma warning restore 1591
