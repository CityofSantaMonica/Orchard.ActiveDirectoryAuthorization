using System.Web;
using ActiveDirectoryAuthorization.Models;
using Orchard.Environment.Extensions;
using Orchard.Security;
using Orchard.Environment;
using Orchard;
using Orchard.Settings;

namespace ActiveDirectoryAuthorization.Services
{
    [OrchardSuppressDependency("Orchard.Security.Providers.FormsAuthenticationService")]
    public class ActiveDirectoryAuthenticationService : IAuthenticationService
    {
        private readonly Work<IMembershipService> _membershipService;
        private readonly IWorkContextAccessor _workContextAccessor;
        private readonly ISiteService _siteService;

        private bool _impersonateSiteOwner = false;

        public ActiveDirectoryAuthenticationService(
            Work<IMembershipService> membershipService,
            ISiteService siteService,
            IWorkContextAccessor workContextAccessor)
        {
            _membershipService = membershipService;
            _siteService = siteService;
            _workContextAccessor = workContextAccessor;
        }

        public void SignIn(IUser user, bool createPersistentCookie)
        {
            // users are already signed in.
        }

        public void SignOut()
        {
           // users aren't able to sign out because they're automatically logged in.
        }

        public void SetAuthenticatedUserForRequest(IUser user)
        {
            var ctx = _workContextAccessor.GetContext();
            if (ctx.CurrentUser == null && user != null && user == GetSiteOwner())
            {
                _impersonateSiteOwner = true;
            }
            else
            {
                _impersonateSiteOwner = false;
            }

           // users are automatically authenticated via active directory.
        }

        /// <summary>
        /// Overrides the default behaviour to return an instance of ActiveDirectoryUser
        /// based on the current user in the context if a UserPart hasn't been created for
        /// the active directory user yet.
        /// </summary>
        /// <returns></returns>
        public IUser GetAuthenticatedUser()
        {
            if (_impersonateSiteOwner)
                return GetSiteOwner();

            if (HttpContext.Current == null || HttpContext.Current.User == null)
                return null;

            // attempts to get the user from the UserPart data store.
            var user = _membershipService.Value.GetUser(HttpContext.Current.User.Identity.Name);

            // if the user doesn't exist in the UserPart data store, then the
            // current active directory user is returned instead.
            if (user == null)
                user = new ActiveDirectoryUser();

            return user;
        }

        private IUser GetSiteOwner()
        {
            var superUser = _siteService.GetSiteSettings().SuperUser;
            return _membershipService.Value.GetUser(superUser);
        }
    }
}
